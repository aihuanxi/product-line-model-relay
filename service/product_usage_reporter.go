package service

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const (
	ProductResourceContract = "resource-billing/v1"
	ProductResourceAudience = "model-relay"
)

type ProductUsageReporter struct {
	endpoint string
	token    string
	client   *http.Client
	scope    model.ProductCallScope
}

func NewProductUsageReporter(baseURL, token string, scope model.ProductCallScope) (*ProductUsageReporter, error) {
	target, err := url.Parse(baseURL)
	if err != nil || target.Hostname() == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || token == "" {
		return nil, errors.New("product metering requires a URL and service token")
	}
	address, _ := netip.ParseAddr(target.Hostname())
	if target.Scheme != "https" && !(target.Scheme == "http" && address.IsLoopback()) {
		return nil, errors.New("product metering requires HTTPS or a loopback test URL")
	}
	if scope.ProductID == "" || scope.Environment == "" || scope.PartitionID == "" {
		return nil, errors.New("product metering requires a product, environment and partition")
	}
	return &ProductUsageReporter{
		endpoint: strings.TrimRight(target.String(), "/"), token: token, scope: scope,
		client: &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type productMeasurement struct {
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	EvidenceRef  string `json:"evidenceRef,omitempty"`
	InputTokens  *int64 `json:"inputTokens,omitempty"`
	OutputTokens *int64 `json:"outputTokens,omitempty"`
}

type productUsageEvent struct {
	EventID           string             `json:"eventId"`
	ObjectID          string             `json:"objectId"`
	AttemptID         string             `json:"attemptId"`
	ProductID         string             `json:"productId"`
	Environment       string             `json:"environment"`
	Audience          string             `json:"audience"`
	ProductUserID     string             `json:"productUserId"`
	WorkspaceID       *string            `json:"workspaceId"`
	BillingAccountID  string             `json:"billingAccountId"`
	RuntimeInstanceID string             `json:"runtimeInstanceId"`
	AccessID          string             `json:"accessId"`
	IssuanceID        string             `json:"issuanceId"`
	AllocationID      string             `json:"allocationId"`
	ResourceID        string             `json:"resourceId"`
	AdmittedAt        time.Time          `json:"admittedAt"`
	Measurement       productMeasurement `json:"measurement"`
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
	if err := r.scope.ReviewExpired(ctx, now); err != nil {
		return err
	}
	due, err := r.scope.Due(ctx, now, 50)
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
			EventID: "usage-" + call.AttemptID, ObjectID: call.CallID, AttemptID: call.AttemptID,
			ProductID: call.ProductID, Environment: call.Environment, Audience: ProductResourceAudience,
			ProductUserID: call.ProductUserID, BillingAccountID: call.BillingAccountID, RuntimeInstanceID: call.InstanceID,
			AccessID: call.AccessID, IssuanceID: call.IssuanceID, AllocationID: call.AllocationID, ResourceID: call.Model,
			AdmittedAt:  time.UnixMilli(call.CreatedAt).UTC(),
			Measurement: productMeasurement{EvidenceRef: cmp.Or(call.ProviderRequest, call.ProviderReply, call.AttemptID)},
		}
		if call.WorkspaceID != "" {
			event.WorkspaceID = &call.WorkspaceID
		}
		if call.State == model.ProductCallConfirmed {
			event.Measurement.Status = "confirmed"
			event.Measurement.InputTokens, event.Measurement.OutputTokens = call.InputTokens, call.OutputTokens
			if call.ReviewEvidence != "" {
				event.EventID += "-confirmed"
				event.Measurement.EvidenceRef = call.ReviewEvidence
			}
		} else {
			event.Measurement.Status = "pending"
			event.Measurement.Reason = "provider_usage_unavailable"
		}
		events = append(events, event)
		claimed = append(claimed, call)
	}
	if len(events) == 0 {
		return nil
	}
	batch := struct {
		Events []productUsageEvent `json:"events"`
	}{events}
	var ack struct {
		Results []struct {
			EventID string `json:"eventId"`
			Status  string `json:"status"`
		} `json:"results"`
	}
	if err := r.ResourceJSON(ctx, http.MethodPost, "/internal/v1/usage:ingest", batch, &ack); err != nil {
		return err
	}
	accepted := make(map[string]string, len(ack.Results))
	for _, result := range ack.Results {
		accepted[result.EventID] = result.Status
	}
	var ackErrors error
	missing := 0
	for index, call := range claimed {
		status := accepted[events[index].EventID]
		if status == "posted" || (status == "pending" && call.State == model.ProductCallPendingReview) {
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

// ResourceJSON is used by the background controls and the usage reporter.
func (r *ProductUsageReporter) ResourceJSON(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		payload, err := common.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.endpoint+path, body)
	if err != nil {
		return errors.New("build resource billing request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return errors.New("resource billing unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("resource billing %s returned HTTP %d", path, resp.StatusCode)
	}
	if resp.Header.Get("X-Huanxi-Contract-Version") != ProductResourceContract {
		return errors.New("unexpected resource billing response version")
	}
	if err := common.DecodeJsonBody(io.LimitReader(resp.Body, 8<<20), output); err != nil {
		return errors.New("invalid resource billing response")
	}
	return nil
}
