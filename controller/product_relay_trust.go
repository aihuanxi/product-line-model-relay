package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/service"
	"github.com/golang-jwt/jwt/v5"
)

type productRelayConfig struct {
	Issuer            string   `json:"issuer"`
	ProductID         string   `json:"product_id"`
	Environment       string   `json:"environment"`
	Model             string   `json:"model"`
	ChannelID         int      `json:"channel_id"`
	MaxOutputTokens   uint     `json:"max_output_tokens"`
	TrustFile         string   `json:"trust_file"`
	BillingURL        string   `json:"billing_url"`
	PartitionID       string   `json:"partition_id"`
	BillingAccountIDs []string `json:"billing_account_ids"`
}

type productVerificationKey struct {
	KeyID       string     `json:"kid"`
	Type        string     `json:"kty"`
	Curve       string     `json:"crv"`
	Algorithm   string     `json:"alg"`
	Use         string     `json:"use"`
	PublicKey   string     `json:"x"`
	VerifyUntil *time.Time `json:"verifyUntil"`
}

type productVerificationSnapshot struct {
	ContractVersion string                   `json:"contractVersion"`
	ProductID       string                   `json:"productId"`
	Environment     string                   `json:"environment"`
	Audience        string                   `json:"audience"`
	Version         uint64                   `json:"version"`
	Keys            []productVerificationKey `json:"keys"`
	Instances       []struct {
		ID               string `json:"runtimeInstanceId"`
		Generation       int    `json:"generation"`
		CredentialSHA256 string `json:"credentialSha256"`
	} `json:"instances"`
	Revocations []struct {
		AccessID  string    `json:"accessId"`
		RevokedAt time.Time `json:"revokedAt"`
	} `json:"revocations"`
}

type productAllocation struct {
	ID               string `json:"allocationId"`
	BillingAccountID string `json:"billingAccountId"`
	Audience         string `json:"audience"`
	PartitionID      string `json:"partitionId"`
	AdmissionLimit   int64  `json:"admissionLimit"`
}

type productVerificationMaterial struct {
	Snapshot    productVerificationSnapshot  `json:"snapshot"`
	Allocations map[string]productAllocation `json:"allocations"`
}

type productTrustedKey struct {
	publicKey   ed25519.PublicKey
	verifyUntil *time.Time
}

type productRelayTrust struct {
	material  productVerificationMaterial
	keys      map[string]productTrustedKey
	instances map[string][sha256.Size]byte
	revoked   map[string]bool
}

type productGrant struct {
	jwt.RegisteredClaims
	AccessID         string   `json:"accessId"`
	ProductID        string   `json:"productId"`
	Environment      string   `json:"environment"`
	WorkspaceID      string   `json:"workspaceId"`
	OrganizationID   string   `json:"organizationId"`
	InstanceID       string   `json:"runtimeInstanceId"`
	BillingAccountID string   `json:"billingAccountId"`
	Scope            []string `json:"scope"`
}

type ProductRelay struct {
	config   productRelayConfig
	trust    atomic.Pointer[productRelayTrust]
	reporter *service.ProductUsageReporter
}

func LoadProductRelay(path, serviceToken string) (*ProductRelay, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r := &ProductRelay{}
	if err := common.Unmarshal(data, &r.config); err != nil {
		return nil, errors.New("invalid product relay configuration JSON")
	}
	cfg := r.config
	if cfg.Issuer == "" || !validProductID(cfg.ProductID) || !validProductID(cfg.Environment) ||
		cfg.Model == "" || len(cfg.Model) > 128 || cfg.ChannelID <= 0 || cfg.TrustFile == "" ||
		cfg.MaxOutputTokens == 0 || helper.ExceedsMaxTokensLimit(&cfg.MaxOutputTokens) ||
		!validProductID(cfg.PartitionID) || len(cfg.BillingAccountIDs) == 0 ||
		slices.ContainsFunc(cfg.BillingAccountIDs, func(id string) bool { return !validProductID(id) }) {
		return nil, errors.New("incomplete or invalid product relay configuration")
	}
	r.reporter, err = service.NewProductUsageReporter(cfg.BillingURL, serviceToken, model.ProductCallScope{
		ProductID: cfg.ProductID, Environment: cfg.Environment, PartitionID: cfg.PartitionID,
	})
	if err != nil {
		return nil, err
	}
	data, err = os.ReadFile(cfg.TrustFile)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		common.SysError("unable to read cached product verification")
		return r, nil
	}
	var material productVerificationMaterial
	if err := common.Unmarshal(data, &material); err != nil {
		common.SysError("invalid product verification cache JSON")
		return r, nil
	}
	trust, err := r.compileTrust(material)
	if err != nil {
		common.SysError("unable to restore cached product verification: " + err.Error())
		return r, nil
	}
	r.trust.Store(trust)
	return r, nil
}

func (r *ProductRelay) compileTrust(material productVerificationMaterial) (*productRelayTrust, error) {
	snapshot := material.Snapshot
	if snapshot.ContractVersion != service.ProductResourceContract || snapshot.Audience != service.ProductResourceAudience ||
		snapshot.ProductID != r.config.ProductID || snapshot.Environment != r.config.Environment {
		return nil, errors.New("unexpected product verification realm or contract")
	}
	trust := &productRelayTrust{
		material:  material,
		keys:      make(map[string]productTrustedKey, len(snapshot.Keys)),
		instances: make(map[string][sha256.Size]byte, len(snapshot.Instances)),
		revoked:   make(map[string]bool, len(snapshot.Revocations)),
	}
	for _, key := range snapshot.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(key.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize || !validProductID(key.KeyID) ||
			key.Type != "OKP" || key.Curve != "Ed25519" || key.Algorithm != "EdDSA" || key.Use != "sig" {
			return nil, errors.New("invalid product verification key")
		}
		trust.keys[key.KeyID] = productTrustedKey{ed25519.PublicKey(raw), key.VerifyUntil}
	}
	for _, instance := range snapshot.Instances {
		raw, err := hex.DecodeString(instance.CredentialSHA256)
		if err != nil || len(raw) != sha256.Size || !validProductID(instance.ID) || instance.Generation < 1 {
			return nil, errors.New("invalid product verification instance")
		}
		trust.instances[instance.ID] = [sha256.Size]byte(raw)
	}
	for _, revocation := range snapshot.Revocations {
		trust.revoked[revocation.AccessID] = true
	}
	for account, allocation := range material.Allocations {
		if !slices.Contains(r.config.BillingAccountIDs, account) || !r.validAllocation(account, allocation) {
			return nil, errors.New("invalid product allocation")
		}
	}
	return trust, nil
}

func (r *ProductRelay) validAllocation(account string, allocation productAllocation) bool {
	return allocation.BillingAccountID == account && allocation.Audience == service.ProductResourceAudience &&
		allocation.PartitionID == r.config.PartitionID && validProductID(allocation.ID) && allocation.AdmissionLimit >= 0
}

func (r *ProductRelay) Run(ctx context.Context) {
	var reporter sync.WaitGroup
	reporter.Go(func() { r.reporter.Run(ctx) })
	defer reporter.Wait()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	nextAccount := 0
	for ctx.Err() == nil {
		if err := r.syncTrust(ctx, &nextAccount); err != nil && ctx.Err() == nil {
			common.SysError("sync product verification: " + err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *ProductRelay) syncTrust(ctx context.Context, nextAccount *int) error {
	var snapshot productVerificationSnapshot
	if err := r.reporter.ResourceJSON(ctx, http.MethodGet, "/internal/v1/resource-verification/snapshot", nil, &snapshot); err != nil {
		return err
	}
	current := r.trust.Load()
	material := productVerificationMaterial{Snapshot: snapshot}
	if current != nil {
		if snapshot.Version < current.material.Snapshot.Version {
			return errors.New("product verification snapshot version went backwards")
		}
		material.Allocations = current.material.Allocations
	}
	if current == nil || snapshot.Version > current.material.Snapshot.Version {
		if err := r.storeTrust(material); err != nil {
			return err
		}
	} else {
		material = current.material
	}

	// Publish revocations before provisioning. Bound the entire allocation pass
	// so a slow account cannot hold up the next verification snapshot.
	provisioning, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	previous := material.Allocations
	material.Allocations = make(map[string]productAllocation, len(previous))
	maps.Copy(material.Allocations, previous)
	var allocationErr error
	accounts := r.config.BillingAccountIDs
	for range len(accounts) {
		if provisioning.Err() != nil {
			break
		}
		account := accounts[*nextAccount]
		*nextAccount = (*nextAccount + 1) % len(accounts)
		if _, exists := material.Allocations[account]; exists {
			continue
		}
		var allocation productAllocation
		request := map[string]string{"billingAccountId": account, "partitionId": r.config.PartitionID}
		if err := r.reporter.ResourceJSON(provisioning, http.MethodPost, "/internal/v1/allocations", request, &allocation); err != nil {
			allocationErr = errors.Join(allocationErr, err)
			continue
		}
		if !r.validAllocation(account, allocation) {
			allocationErr = errors.Join(allocationErr, errors.New("invalid product allocation"))
			continue
		}
		material.Allocations[account] = allocation
	}
	if len(material.Allocations) > len(previous) {
		allocationErr = errors.Join(allocationErr, r.storeTrust(material))
	}
	return allocationErr
}

func (r *ProductRelay) storeTrust(material productVerificationMaterial) error {
	trust, err := r.compileTrust(material)
	if err != nil {
		return err
	}
	data, err := common.Marshal(material)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(r.config.TrustFile), ".product-verification-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), r.config.TrustFile); err != nil {
		return err
	}
	r.trust.Store(trust)
	return nil
}

func (r *ProductRelay) authorize(raw, credential string, trust *productRelayTrust, now time.Time) (*productGrant, error) {
	grant := &productGrant{}
	_, err := jwt.ParseWithClaims(raw, grant, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key, exists := trust.keys[kid]
		_, hasCriticalHeader := token.Header["crit"]
		if token.Header["typ"] != "resource+jwt" || !exists || hasCriticalHeader ||
			(key.verifyUntil != nil && !now.Before(*key.verifyUntil)) {
			return nil, errors.New("untrusted resource token key or type")
		}
		return key.publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(r.config.Issuer), jwt.WithAudience(service.ProductResourceAudience),
		jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return nil, errors.New("invalid resource credential")
	}
	// The v1 allowance applies to issuance time. Expiry still uses the local clock.
	if grant.IssuedAt == nil || grant.IssuedAt.After(now.Add(5*time.Second)) || !grant.ExpiresAt.After(grant.IssuedAt.Time) ||
		grant.ExpiresAt.Sub(grant.IssuedAt.Time) > time.Hour || len(grant.Audience) != 1 ||
		grant.ProductID != r.config.ProductID || grant.Environment != r.config.Environment ||
		!validProductID(grant.Subject) || !validProductID(grant.AccessID) || !validProductID(grant.ID) ||
		!validProductID(grant.InstanceID) || !validProductID(grant.BillingAccountID) ||
		(grant.WorkspaceID != "" && !validProductID(grant.WorkspaceID)) ||
		(grant.OrganizationID != "" && (!validProductID(grant.OrganizationID) || grant.WorkspaceID == "")) ||
		trust.revoked[grant.AccessID] {
		return nil, errors.New("invalid or revoked resource grant")
	}
	expected, exists := trust.instances[grant.InstanceID]
	provided := sha256.Sum256([]byte(credential))
	if !exists || subtle.ConstantTimeCompare(provided[:], expected[:]) != 1 {
		return nil, errors.New("invalid resource instance credential")
	}
	return grant, nil
}
