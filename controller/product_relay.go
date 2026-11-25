package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relay"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	ProductChatPath    = "/product/v1/chat/completions"
	productProofHeader = "X-Huanxi-Instance-Credential"
	productCallTimeout = 15 * time.Minute
)

func validProductID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && (index == 0 || !strings.ContainsRune("-_.:/@", char)) {
			return false
		}
	}
	return true
}

func productError(c *gin.Context, status int, code, messageKey string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"type": code, "message": i18n.T(c, messageKey)}})
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
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", i18n.MsgProductCredentialsRequired)
		return
	}
	scheme, rawToken, _ := strings.Cut(auth[0], " ")
	if !strings.EqualFold(scheme, "Bearer") || rawToken == "" || len(rawToken) > 8192 ||
		len(proofs[0]) < 32 || len(proofs[0]) > 512 {
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", i18n.MsgProductInvalidCredential)
		return
	}
	trust := r.trust.Load()
	if trust == nil {
		productError(c, http.StatusServiceUnavailable, "product_verification_unavailable", i18n.MsgProductVerificationUnavailable)
		return
	}
	grant, err := r.authorize(rawToken, proofs[0], trust, time.Now())
	if err != nil {
		logger.LogWarn(c, "product relay denied: "+err.Error())
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", i18n.MsgProductInvalidCredential)
		return
	}
	mediaType, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		productError(c, http.StatusUnsupportedMediaType, "unsupported_media_type", i18n.MsgProductMediaType)
		return
	}
	storage, err := common.GetBodyStorage(c)
	if err != nil {
		if common.IsRequestBodyTooLargeError(err) || errors.Is(err, common.ErrRequestBodyTooLarge) {
			productError(c, http.StatusRequestEntityTooLarge, "invalid_request_error", i18n.MsgProductBodyTooLarge)
		} else {
			productError(c, http.StatusBadRequest, "invalid_request_error", i18n.MsgProductReadBody)
		}
		return
	}
	reader, err := storage.NewReader()
	if err != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", i18n.MsgProductReadBody)
		return
	}
	digest := sha256.New()
	_, err = io.Copy(digest, reader)
	_ = reader.Close()
	if err != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", i18n.MsgProductReadBody)
		return
	}
	bodyHash := hex.EncodeToString(digest.Sum(nil))

	// Keep the ingress path in request logs and give the channel only native chat inputs.
	upstream := c.Request.Clone(c.Request.Context())
	upstream.URL = &url.URL{Path: ProductChatPath}
	upstream.RequestURI = upstream.URL.Path
	upstream.Header = http.Header{"Content-Type": {"application/json"}}
	upstream.Trailer = nil
	c.Request = upstream

	request, err := helper.GetAndValidateTextRequest(c, relayconstant.RelayModeChatCompletions)
	if err != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", i18n.MsgProductInvalidChat)
		return
	}
	if request.Model != r.config.Model || !slices.Contains(grant.Scope, request.Model) {
		productError(c, http.StatusForbidden, "model_not_allowed", i18n.MsgProductModelScope)
		return
	}
	if request.N != nil && *request.N != 1 {
		productError(c, http.StatusBadRequest, "invalid_request_error", i18n.MsgProductSingleCompletion)
		return
	}
	if request.MaxTokens != nil && request.MaxCompletionTokens != nil {
		productError(c, http.StatusBadRequest, "invalid_request_error", i18n.MsgProductSingleLimit)
		return
	}
	for _, limit := range []*uint{request.MaxTokens, request.MaxCompletionTokens} {
		if limit != nil && (*limit == 0 || *limit > r.config.MaxOutputTokens) {
			productError(c, http.StatusBadRequest, "invalid_request_error", i18n.MsgProductOutputLimit)
			return
		}
	}
	if request.MaxTokens == nil && request.MaxCompletionTokens == nil {
		request.MaxTokens = &r.config.MaxOutputTokens
	}

	admittedAt := time.Now()
	if latest := r.trust.Load(); latest != trust {
		trust = latest
		grant, err = r.authorize(rawToken, proofs[0], trust, admittedAt)
		if err != nil {
			logger.LogWarn(c, "product relay denied: "+err.Error())
			productError(c, http.StatusUnauthorized, "invalid_resource_credential", i18n.MsgProductInvalidCredential)
			return
		}
	}
	if !admittedAt.Before(grant.ExpiresAt.Time) {
		productError(c, http.StatusUnauthorized, "invalid_resource_credential", i18n.MsgProductInvalidCredential)
		return
	}
	deadline := admittedAt.Add(productCallTimeout)
	allocation := trust.material.Allocations[grant.BillingAccountID]
	callID := sha256.Sum256([]byte(grant.Environment + "\x00" + grant.ProductID + "\x00" + grant.Subject + "\x00" + keys[0]))
	allocationKey := sha256.Sum256([]byte(grant.Environment + "\x00" + grant.ProductID + "\x00" + allocation.ID))
	scope := model.ProductCallScope{ProductID: grant.ProductID, Environment: grant.Environment, PartitionID: r.config.PartitionID}
	call, chosen, err := model.BeginProductModelCall(c.Request.Context(), model.ProductModelCall{
		CallID: hex.EncodeToString(callID[:]), AttemptID: uuid.NewString(), RequestHash: bodyHash, State: model.ProductCallInFlight,
		ProductID: grant.ProductID, Environment: grant.Environment, DeliveryScope: scope.Key(), ProductUserID: grant.Subject,
		WorkspaceID: grant.WorkspaceID, BillingAccountID: grant.BillingAccountID, OrganizationID: grant.OrganizationID, InstanceID: grant.InstanceID,
		AccessID: grant.AccessID, IssuanceID: grant.ID, AllocationID: allocation.ID, Model: request.Model, ChannelID: r.config.ChannelID,
		CreatedAt:   admittedAt.UnixMilli(),
		ReviewAfter: deadline.Add(30 * time.Second).Unix(),
	}, hex.EncodeToString(allocationKey[:]), allocation.AdmissionLimit)
	if err != nil {
		if errors.Is(err, model.ErrProductAllocationExhausted) {
			productError(c, http.StatusTooManyRequests, "product_allocation_exhausted", i18n.MsgProductAllocationExhausted)
		} else {
			logger.LogError(c, "unable to persist product model admission")
			productError(c, http.StatusServiceUnavailable, "product_metering_unavailable", i18n.MsgProductRecordCall)
		}
		return
	}
	if !chosen && (call.RequestHash != bodyHash || call.InstanceID != grant.InstanceID ||
		call.BillingAccountID != grant.BillingAccountID || call.OrganizationID != grant.OrganizationID || call.WorkspaceID != grant.WorkspaceID) {
		productError(c, http.StatusConflict, "idempotency_conflict", i18n.MsgProductIdempotencyConflict)
		return
	}
	c.Header(relaycommon.ProductCallIDHeader, call.CallID)
	c.Header(relaycommon.ProductAttemptIDHeader, call.AttemptID)
	if !chosen {
		result := gin.H{"call_id": call.CallID, "attempt_id": call.AttemptID, "status": call.State}
		if call.State == model.ProductCallConfirmed {
			result["usage"] = gin.H{"prompt_tokens": call.InputTokens, "completion_tokens": call.OutputTokens, "total_tokens": call.TotalTokens}
		}
		c.JSON(http.StatusOK, result)
		return
	}

	attemptContext, cancel := context.WithDeadline(c.Request.Context(), deadline)
	defer cancel()
	c.Request = c.Request.WithContext(attemptContext)
	attempt := &relaycommon.ProductRelayAttempt{ID: call.AttemptID}
	usageSaved := false
	persist := func(state string) error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(attemptContext), 3*time.Second)
		defer cancel()
		if validProductID(attempt.ProviderRequest) {
			call.ProviderRequest = attempt.ProviderRequest
		}
		if validProductID(attempt.ProviderReply) {
			call.ProviderReply = attempt.ProviderReply
		}
		if len(attempt.UpstreamModel) <= 255 {
			call.UpstreamModel = attempt.UpstreamModel
		}
		if attempt.Usage != nil {
			call.InputTokens, call.OutputTokens, call.TotalTokens = &attempt.Usage.InputTokens, &attempt.Usage.OutputTokens, &attempt.Usage.TotalTokens
		}
		if state == model.ProductCallInFlight {
			return call.RecordProviderEvidence(ctx)
		}
		return call.Finish(ctx, state)
	}
	attempt.SaveEvidence = func() error {
		if attempt.Usage == nil {
			return persist(model.ProductCallInFlight)
		}
		err := persist(model.ProductCallConfirmed)
		usageSaved = err == nil
		return err
	}
	defer func() {
		if usageSaved {
			return
		}
		state := model.ProductCallPendingReview
		if attempt.Usage != nil {
			state = model.ProductCallConfirmed
		} else if !attempt.Dispatched || slices.Contains([]int{400, 401, 403, 404, 422, 429}, attempt.UpstreamStatus) {
			state = model.ProductCallRejected
		}
		if err := persist(state); err != nil {
			logger.LogError(c, "unable to finish product model attempt "+call.AttemptID)
		}
	}()

	channel, err := model.CacheGetChannel(r.config.ChannelID)
	if err != nil || channel.Status != common.ChannelStatusEnabled || channel.Type != constant.ChannelTypeOpenAI ||
		!slices.Contains(channel.GetModels(), request.Model) || len(channel.GetParamOverride()) != 0 {
		productError(c, http.StatusServiceUnavailable, "product_channel_unavailable", i18n.MsgProductChannelUnavailable)
		return
	}
	if apiErr := middleware.SetupContextForSelectedChannel(c, channel, request.Model); apiErr != nil {
		productError(c, http.StatusServiceUnavailable, "product_channel_unavailable", i18n.MsgProductChannelUnavailable)
		return
	}
	info := relaycommon.GenRelayInfoOpenAI(c, request)
	info.RelayMode = relayconstant.RelayModeChatCompletions
	info.RequestURLPath = "/v1/chat/completions"
	info.ProductAttempt = attempt
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
