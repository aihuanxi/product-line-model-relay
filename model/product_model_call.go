package model

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	ProductCallInFlight      = "in_flight"
	ProductCallConfirmed     = "confirmed"
	ProductCallRejected      = "rejected"
	ProductCallPendingReview = "pending_review"
)

var ErrProductAllocationExhausted = errors.New("product model allocation exhausted")

type ProductModelCall struct {
	CallID          string `gorm:"size:64;primaryKey"`
	AttemptID       string `gorm:"size:36;not null;uniqueIndex"`
	RequestHash     string `gorm:"size:64;not null"`
	ProductID       string `gorm:"size:128;not null"`
	Environment     string `gorm:"size:128;not null"`
	ProductUserID   string `gorm:"size:128;not null"`
	WorkspaceID     string `gorm:"size:128;not null"`
	PayerID         string `gorm:"size:128;not null"`
	PayerType       string `gorm:"size:16;not null"`
	InstanceID      string `gorm:"size:128;not null"`
	AccessID        string `gorm:"size:128;not null"`
	AllocationID    string `gorm:"size:128;not null"`
	Model           string `gorm:"size:255;not null"`
	ChannelID       int
	UpstreamModel   string `gorm:"size:255"`
	ProviderRequest string `gorm:"size:128"`
	ProviderReply   string `gorm:"size:128"`
	State           string `gorm:"size:24;not null;index:idx_product_call_review"`
	InputTokens     *int64
	OutputTokens    *int64
	TotalTokens     *int64
	CreatedAt       int64
	FinishedAt      int64
	ReviewAfter     int64 `gorm:"index:idx_product_call_review"`
	DeliverAfter    int64 `gorm:"index"`
	DeliveryTries   int
	DeliveredAt     int64
}

type ProductModelAllocation struct {
	ID       string `gorm:"size:64;primaryKey"`
	Admitted int64  `gorm:"not null"`
}

// BeginProductModelCall reserves the call and one admission in the same
// transaction. The stored attempt identifies the winning replica.
func BeginProductModelCall(ctx context.Context, candidate ProductModelCall, allocationKey string, maxCalls int64) (ProductModelCall, bool, error) {
	var stored ProductModelCall
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		conflict := clause.OnConflict{DoNothing: true}
		if err := tx.Clauses(conflict).Create(&candidate).Error; err != nil {
			return err
		}
		if err := tx.First(&stored, "call_id = ?", candidate.CallID).Error; err != nil {
			return err
		}
		if stored.AttemptID != candidate.AttemptID {
			return nil
		}
		if err := tx.Clauses(conflict).Create(&ProductModelAllocation{ID: allocationKey}).Error; err != nil {
			return err
		}
		admission := tx.Model(&ProductModelAllocation{}).
			Where("id = ? AND admitted < ?", allocationKey, maxCalls).
			UpdateColumn("admitted", gorm.Expr("admitted + 1"))
		if admission.Error != nil {
			return admission.Error
		}
		if admission.RowsAffected == 0 {
			return ErrProductAllocationExhausted
		}
		return nil
	})
	return stored, err == nil && stored.AttemptID == candidate.AttemptID, err
}

func (call ProductModelCall) RecordProviderEvidence(ctx context.Context) error {
	return DB.WithContext(ctx).Model(&ProductModelCall{}).
		Where("call_id = ? AND state = ?", call.CallID, ProductCallInFlight).
		Updates(map[string]any{
			"provider_request": call.ProviderRequest, "provider_reply": call.ProviderReply, "upstream_model": call.UpstreamModel,
		}).Error
}

func (call ProductModelCall) Finish(ctx context.Context, state string) error {
	now := time.Now().Unix()
	due := int64(0)
	if state == ProductCallConfirmed || state == ProductCallPendingReview {
		due = now
	}
	update := DB.WithContext(ctx).Model(&ProductModelCall{}).
		Where("call_id = ? AND state = ?", call.CallID, ProductCallInFlight).
		Updates(map[string]any{
			"state": state, "finished_at": now, "deliver_after": due,
			"provider_request": call.ProviderRequest, "provider_reply": call.ProviderReply, "upstream_model": call.UpstreamModel,
			"input_tokens": call.InputTokens, "output_tokens": call.OutputTokens, "total_tokens": call.TotalTokens,
		})
	if update.Error == nil && update.RowsAffected != 1 {
		return errors.New("product model attempt is no longer in flight")
	}
	return update.Error
}

// ReviewExpiredProductModelCalls recovers attempts whose process died before
// recording a result. The original attempt remains the authority for review.
func ReviewExpiredProductModelCalls(ctx context.Context, now int64) error {
	return DB.WithContext(ctx).Model(&ProductModelCall{}).
		Where("state = ? AND review_after <= ?", ProductCallInFlight, now).
		Updates(map[string]any{"state": ProductCallPendingReview, "finished_at": now, "deliver_after": now}).Error
}

func DueProductModelCalls(ctx context.Context, now int64, limit int) ([]ProductModelCall, error) {
	var calls []ProductModelCall
	err := DB.WithContext(ctx).Where("deliver_after > 0 AND deliver_after <= ?", now).
		Order("deliver_after, call_id").Limit(limit).Find(&calls).Error
	return calls, err
}

func (call ProductModelCall) ClaimDelivery(ctx context.Context, next int64) (bool, error) {
	result := DB.WithContext(ctx).Model(&ProductModelCall{}).
		Where("call_id = ? AND deliver_after = ? AND delivery_tries = ?", call.CallID, call.DeliverAfter, call.DeliveryTries).
		Updates(map[string]any{"deliver_after": next, "delivery_tries": gorm.Expr("delivery_tries + 1")})
	return result.RowsAffected == 1, result.Error
}

func (call ProductModelCall) AckDelivery(ctx context.Context, now int64) error {
	return DB.WithContext(ctx).Model(&ProductModelCall{}).
		Where("call_id = ? AND delivery_tries = ?", call.CallID, call.DeliveryTries+1).
		Updates(map[string]any{"deliver_after": 0, "delivered_at": now}).Error
}
