package controller

import (
	"errors"
	"math"
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func GetProductModelCall(c *gin.Context) {
	var call model.ProductModelCall
	err := model.DB.WithContext(c.Request.Context()).Take(&call, "call_id = ?", c.Param("call_id")).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			productError(c, http.StatusNotFound, "product_call_not_found", i18n.MsgProductCallNotFound)
		} else {
			logger.LogError(c, "unable to read product model attempt for review")
			productError(c, http.StatusServiceUnavailable, "product_metering_unavailable", i18n.MsgProductMeteringUnavailable)
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"call_id": call.CallID, "attempt_id": call.AttemptID, "status": call.State,
		"admitted_at": call.CreatedAt, "model": call.Model, "upstream_model": call.UpstreamModel,
		"channel_id": call.ChannelID, "provider_request_id": call.ProviderRequest, "provider_reply_id": call.ProviderReply,
		"evidence_ref": call.ReviewEvidence, "input_tokens": call.InputTokens, "output_tokens": call.OutputTokens,
	})
}

func ConfirmProductModelUsage(c *gin.Context) {
	var input struct {
		AttemptID    string `json:"attempt_id"`
		EvidenceRef  string `json:"evidence_ref"`
		InputTokens  *int64 `json:"input_tokens"`
		OutputTokens *int64 `json:"output_tokens"`
	}
	callID := c.Param("call_id")
	body := http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	if err := common.DecodeJsonBody(body, &input); err != nil || !validProductID(callID) ||
		!validProductID(input.AttemptID) || !validProductID(input.EvidenceRef) || input.InputTokens == nil || input.OutputTokens == nil ||
		*input.InputTokens < 0 || *input.InputTokens > math.MaxInt32 || *input.OutputTokens < 0 || *input.OutputTokens > math.MaxInt32 {
		productError(c, http.StatusBadRequest, "invalid_usage_confirmation", i18n.MsgProductInvalidConfirmation)
		return
	}
	call := model.ProductModelCall{CallID: callID, AttemptID: input.AttemptID}
	err := call.ConfirmReviewedUsage(c.Request.Context(), input.EvidenceRef, *input.InputTokens, *input.OutputTokens)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{"call_id": call.CallID, "attempt_id": call.AttemptID, "status": model.ProductCallConfirmed})
	case errors.Is(err, gorm.ErrRecordNotFound):
		productError(c, http.StatusNotFound, "product_call_not_found", i18n.MsgProductCallNotFound)
	case errors.Is(err, model.ErrProductConfirmationConflict):
		productError(c, http.StatusConflict, "product_confirmation_conflict", i18n.MsgProductConfirmationConflict)
	default:
		logger.LogError(c, "unable to confirm product model attempt "+call.AttemptID)
		productError(c, http.StatusServiceUnavailable, "product_metering_unavailable", i18n.MsgProductMeteringUnavailable)
	}
}
