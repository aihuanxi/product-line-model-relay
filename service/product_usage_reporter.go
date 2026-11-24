package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

type ProductUsageReporter struct {
	endpoint string
	token    string
	client   *http.Client
}

func NewProductUsageReporter(endpoint, token string) (*ProductUsageReporter, error) {
	target, err := url.Parse(endpoint)
	if err != nil || target.Hostname() == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || token == "" {
		return nil, errors.New("product metering requires a URL and service token")
	}
	address, _ := netip.ParseAddr(target.Hostname())
	if target.Scheme != "https" && !(target.Scheme == "http" && address.IsLoopback()) {
		return nil, errors.New("product metering requires HTTPS or a loopback test URL")
	}
	return &ProductUsageReporter{
		endpoint: target.String(), token: token,
		client: &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type productTokenCounts struct {
	InputTokens  int64 `json:"inputTokens"`
	OutputTokens int64 `json:"outputTokens"`
	TotalTokens  int64 `json:"totalTokens"`
}

type productUsageEvent struct {
	EventID           string              `json:"eventId"`
	CallID            string              `json:"callId"`
	AttemptID         string              `json:"attemptId"`
	ProductID         string              `json:"productId"`
	Environment       string              `json:"environment"`
	ProductUserID     string              `json:"productUserId"`
	WorkspaceID       string              `json:"workspaceId,omitempty"`
	PayerID           string              `json:"payerId"`
	PayerType         string              `json:"payerType"`
	InstanceID        string              `json:"instanceId"`
	AllocationID      string              `json:"allocationId"`
	Model             string              `json:"model"`
	UpstreamModel     string              `json:"upstreamModel,omitempty"`
	ProviderRequestID string              `json:"providerRequestId,omitempty"`
	ProviderReplyID   string              `json:"providerResponseId,omitempty"`
	Status            string              `json:"status"`
	Usage             *productTokenCounts `json:"usage,omitempty"`
	RecordedAt        int64               `json:"recordedAt"`
}

func (r *ProductUsageReporter) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := r.Flush(ctx); err != nil && ctx.Err() == nil {
			common.SysError("report product model usage: " + err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Flush claims one batch before sending it. A missing acknowledgement leaves
// the same event available for retry after its persisted backoff.
func (r *ProductUsageReporter) Flush(ctx context.Context) error {
	now := time.Now().Unix()
	if err := model.ReviewExpiredProductModelCalls(ctx, now); err != nil {
		return err
	}
	due, err := model.DueProductModelCalls(ctx, now, 50)
	if err != nil {
		return err
	}
	claimed := make([]model.ProductModelCall, 0, len(due))
	events := make([]productUsageEvent, 0, len(due))
	for _, call := range due {
		backoff := min(300, 10<<min(call.DeliveryTries, 5))
		won, err := call.ClaimDelivery(ctx, now+int64(backoff))
		if err != nil {
			return err
		}
		if !won {
			continue
		}
		event := productUsageEvent{
			EventID: call.AttemptID, CallID: call.CallID, AttemptID: call.AttemptID,
			ProductID: call.ProductID, Environment: call.Environment, ProductUserID: call.ProductUserID,
			WorkspaceID: call.WorkspaceID, PayerID: call.PayerID, PayerType: call.PayerType, InstanceID: call.InstanceID,
			AllocationID: call.AllocationID, Model: call.Model, UpstreamModel: call.UpstreamModel,
			ProviderRequestID: call.ProviderRequest, ProviderReplyID: call.ProviderReply,
			Status: call.State, RecordedAt: call.FinishedAt,
		}
		if call.InputTokens != nil && call.OutputTokens != nil && call.TotalTokens != nil {
			event.Usage = &productTokenCounts{*call.InputTokens, *call.OutputTokens, *call.TotalTokens}
		}
		events = append(events, event)
		claimed = append(claimed, call)
	}
	if len(events) == 0 {
		return nil
	}
	payload, err := common.Marshal(struct {
		Events []productUsageEvent `json:"events"`
	}{events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("build metering request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return errors.New("metering receiver unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("metering receiver returned HTTP %d", resp.StatusCode)
	}
	var ack struct {
		AcceptedEventIDs []string `json:"acceptedEventIds"`
	}
	if err := common.DecodeJsonBody(io.LimitReader(resp.Body, 65536), &ack); err != nil {
		return errors.New("invalid metering acknowledgement")
	}
	accepted := make(map[string]bool, len(ack.AcceptedEventIDs))
	for _, id := range ack.AcceptedEventIDs {
		accepted[id] = true
	}
	var ackErrors error
	missing := 0
	for _, call := range claimed {
		if accepted[call.AttemptID] {
			ackErrors = errors.Join(ackErrors, call.AckDelivery(ctx, time.Now().Unix()))
		} else {
			missing++
		}
	}
	if missing != 0 {
		ackErrors = errors.Join(ackErrors, fmt.Errorf("metering acknowledgement missing %d event(s)", missing))
	}
	return ackErrors
}
