package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	ProductChatPath    = "/product/v1/chat/completions"
	productProofHeader = "X-Resource-Instance-Proof"
	productJWTType     = "resource+jwt"
	productMaxTTL      = time.Hour
)

type productRelayConfig struct {
	Issuer          string `json:"issuer"`
	Audience        string `json:"audience"`
	Environment     string `json:"environment"`
	Model           string `json:"model"`
	ChannelID       int    `json:"channel_id"`
	MaxOutputTokens uint   `json:"max_output_tokens"`
	TrustFile       string `json:"trust_file"`
}

type productRelayTrust struct {
	version     uint64
	signingKeys map[string]ed25519.PublicKey
	instances   map[string]map[string]ed25519.PublicKey
	revoked     map[string]bool
}

type productGrant struct {
	jwt.RegisteredClaims
	AccessID    string `json:"access_id"`
	ProductID   string `json:"product_id"`
	Environment string `json:"environment"`
	WorkspaceID string `json:"workspace_id"`
	InstanceID  string `json:"instance_id"`
	PayerID     string `json:"payer_id"`
	Model       string `json:"model"`
}

type ProductRelay struct {
	config productRelayConfig
	trust  atomic.Pointer[productRelayTrust]
}

func LoadProductRelay(path string) (*ProductRelay, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	route := &ProductRelay{}
	if err := common.Unmarshal(data, &route.config); err != nil {
		return nil, errors.New("invalid product relay configuration JSON")
	}
	cfg := route.config
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.Environment == "" || cfg.Model == "" ||
		cfg.ChannelID <= 0 || cfg.TrustFile == "" || cfg.MaxOutputTokens == 0 ||
		helper.ExceedsMaxTokensLimit(&cfg.MaxOutputTokens) {
		return nil, errors.New("incomplete or invalid product relay configuration")
	}
	if err := route.reloadTrust(); err != nil {
		return nil, err
	}
	return route, nil
}

func (r *ProductRelay) reloadTrust() error {
	data, err := os.ReadFile(r.config.TrustFile)
	if err != nil {
		return err
	}
	var snapshot struct {
		Version          uint64                       `json:"version"`
		SigningKeys      map[string]string            `json:"signing_keys"`
		Instances        map[string]map[string]string `json:"instances"`
		RevokedAccessIDs []string                     `json:"revoked_access_ids"`
	}
	if err := common.Unmarshal(data, &snapshot); err != nil || snapshot.Version == 0 {
		return errors.New("invalid product relay trust snapshot")
	}
	if current := r.trust.Load(); current != nil && snapshot.Version <= current.version {
		return nil
	}
	trust := &productRelayTrust{
		version:   snapshot.Version,
		instances: make(map[string]map[string]ed25519.PublicKey, len(snapshot.Instances)),
		revoked:   make(map[string]bool, len(snapshot.RevokedAccessIDs)),
	}
	trust.signingKeys, err = productPublicKeys(snapshot.SigningKeys)
	if err != nil {
		return err
	}
	for product, keys := range snapshot.Instances {
		trust.instances[product], err = productPublicKeys(keys)
		if err != nil {
			return err
		}
	}
	for _, id := range snapshot.RevokedAccessIDs {
		trust.revoked[id] = true
	}
	r.trust.Store(trust)
	return nil
}

func productPublicKeys(encoded map[string]string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for id, value := range encoded {
		key, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(key) != ed25519.PublicKeySize || id == "" {
			return nil, errors.New("invalid Ed25519 public key in product relay trust snapshot")
		}
		keys[id] = ed25519.PublicKey(key)
	}
	return keys, nil
}

func (r *ProductRelay) SyncTrust(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.reloadTrust(); err != nil {
				common.SysError(fmt.Sprintf("reload product relay trust: %v", err))
			}
		}
	}
}

func (r *ProductRelay) authorize(raw string, trust *productRelayTrust) (*productGrant, error) {
	grant := &productGrant{}
	_, err := jwt.ParseWithClaims(raw, grant, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key := trust.signingKeys[kid]
		if token.Header["typ"] != productJWTType || key == nil {
			return nil, errors.New("untrusted resource token key or type")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(r.config.Issuer), jwt.WithAudience(r.config.Audience),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, errors.New("invalid resource credential")
	}
	if grant.IssuedAt == nil || !grant.ExpiresAt.After(grant.IssuedAt.Time) ||
		grant.ExpiresAt.Sub(grant.IssuedAt.Time) > productMaxTTL ||
		grant.Environment != r.config.Environment || grant.Model != r.config.Model ||
		!validProductID(grant.Subject) || !validProductID(grant.AccessID) ||
		!validProductID(grant.ProductID) || !validProductID(grant.InstanceID) ||
		!validProductID(grant.PayerID) || (grant.WorkspaceID != "" && !validProductID(grant.WorkspaceID)) ||
		trust.revoked[grant.AccessID] {
		return nil, errors.New("invalid or revoked resource grant")
	}
	if trust.instances[grant.ProductID][grant.InstanceID] == nil {
		return nil, errors.New("unregistered resource instance")
	}
	return grant, nil
}

func validProductID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && !strings.ContainsRune("-_.:", char) {
			return false
		}
	}
	return true
}

func productError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"type": code, "message": message}})
}

func (r *ProductRelay) Chat(c *gin.Context) {
	if r == nil {
		RelayNotFound(c)
		return
	}
	headers := c.Request.Header
	auth := headers.Values("Authorization")
	proofs := headers.Values(productProofHeader)
	keys := headers.Values("Idempotency-Key")
	headers.Del("Authorization")
	headers.Del(productProofHeader)
	headers.Del("Idempotency-Key")
	c.Request.URL.RawQuery = ""
	if len(auth) != 1 || len(proofs) != 1 || len(keys) != 1 || !validProductID(keys[0]) {
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", "A resource credential, instance proof and idempotency key are required.")
		return
	}
	scheme, rawToken, _ := strings.Cut(auth[0], " ")
	if !strings.EqualFold(scheme, "Bearer") || rawToken == "" || len(rawToken) > 8192 {
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", "Invalid resource credential or instance proof.")
		return
	}
	trust := r.trust.Load()
	grant, err := r.authorize(rawToken, trust)
	if err != nil {
		logger.LogWarn(c, "product relay denied: "+err.Error())
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", "Invalid resource credential or instance proof.")
		return
	}
	mediaType, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		productError(c, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
		return
	}
	storage, err := common.GetBodyStorage(c)
	if err != nil {
		if common.IsRequestBodyTooLargeError(err) || errors.Is(err, common.ErrRequestBodyTooLarge) {
			productError(c, http.StatusRequestEntityTooLarge, "invalid_request_error", "Request body is too large.")
		} else {
			productError(c, http.StatusBadRequest, "invalid_request_error", "Unable to read request body.")
		}
		return
	}
	reader, err := storage.NewReader()
	if err != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", "Unable to read request body.")
		return
	}
	digest := sha256.New()
	_, err = io.Copy(digest, reader)
	_ = reader.Close()
	if err != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", "Unable to read request body.")
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(proofs[0])
	message := fmt.Sprintf("product-model-relay-v1\nPOST\n%s\n%x\n%s\n%x",
		ProductChatPath, sha256.Sum256([]byte(rawToken)), keys[0], digest.Sum(nil))
	if err != nil || !ed25519.Verify(trust.instances[grant.ProductID][grant.InstanceID], []byte(message), signature) {
		logger.LogWarn(c, "product relay denied: invalid instance proof")
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", "Invalid resource credential or instance proof.")
		return
	}

	// From here on the channel sees a native chat request and its own credential.
	upstream := c.Request.Clone(c.Request.Context())
	upstream.URL = &url.URL{Path: "/v1/chat/completions"}
	upstream.RequestURI = upstream.URL.Path
	upstream.Header = http.Header{"Content-Type": {"application/json"}}
	upstream.Trailer = nil
	c.Request = upstream

	request, err := helper.GetAndValidateTextRequest(c, relayconstant.RelayModeChatCompletions)
	if err != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", "Invalid chat completions request.")
		return
	}
	if request.Model != grant.Model {
		productError(c, http.StatusForbidden, "model_not_allowed", "The requested model is outside the resource grant.")
		return
	}
	if request.N != nil && *request.N != 1 {
		productError(c, http.StatusBadRequest, "invalid_request_error", "The product route supports a single completion.")
		return
	}
	if request.MaxTokens != nil && request.MaxCompletionTokens != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", "Use one output token limit.")
		return
	}
	for _, limit := range []*uint{request.MaxTokens, request.MaxCompletionTokens} {
		if limit != nil && (*limit == 0 || *limit > r.config.MaxOutputTokens) {
			productError(c, http.StatusBadRequest, "invalid_request_error", "The output token limit is outside the product route limit.")
			return
		}
	}
	if request.MaxTokens == nil && request.MaxCompletionTokens == nil {
		request.MaxTokens = &r.config.MaxOutputTokens
	}

	channel, err := model.CacheGetChannel(r.config.ChannelID)
	if err != nil || channel.Status != common.ChannelStatusEnabled || channel.Type != constant.ChannelTypeOpenAI ||
		!slices.Contains(channel.GetModels(), request.Model) || len(channel.GetParamOverride()) != 0 {
		productError(c, http.StatusServiceUnavailable, "product_channel_unavailable", "The configured product channel is unavailable.")
		return
	}
	if apiErr := middleware.SetupContextForSelectedChannel(c, channel, request.Model); apiErr != nil {
		productError(c, http.StatusServiceUnavailable, "product_channel_unavailable", "The configured product channel is unavailable.")
		return
	}
	info := relaycommon.GenRelayInfoOpenAI(c, request)
	info.IsProductRelay = true
	if apiErr := relay.TextHelper(c, info); apiErr != nil {
		if c.Writer.Written() {
			if info.IsStream {
				writeRelayStreamError(c, info.RelayFormat, apiErr)
			}
			return
		}
		c.Header("Content-Type", "application/json; charset=utf-8")
		c.JSON(apiErr.StatusCode, gin.H{"error": apiErr.ToOpenAIError(common.UpstreamAddresses(c)...)})
	}
}
