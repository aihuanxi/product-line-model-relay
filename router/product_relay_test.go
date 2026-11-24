package router

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProductModelRoute(t *testing.T) {
	h := newRelayHarness(t)
	require.NoError(t, model.DB.AutoMigrate(&model.ProductModelCall{}, &model.ProductModelAllocation{}))
	channel := h.newChannel(constant.ChannelTypeOpenAI, "fake-upstream-key")
	channel.HeaderOverride = common.GetPointer(`{"*":""}`)
	h.install(t, channel)
	fixture := newProductRouteFixture(t, channel.Id, "http://127.0.0.1:1/internal/v1/usage:ingest", 10)
	engine := fixture.router(t)

	jsonReply := fixture.post(t, engine, "json", relayTestBody)
	require.Equal(t, http.StatusOK, jsonReply.Code, jsonReply.Body.String())
	assert.Contains(t, jsonReply.Body.String(), `"content":"hi"`)

	streamBody := strings.TrimSuffix(relayTestBody, "}") + `,"stream":true,"stream_options":{"include_usage":false}}`
	sseReply := fixture.post(t, engine, "sse", streamBody)
	require.Equal(t, http.StatusOK, sseReply.Code, sseReply.Body.String())
	assert.Contains(t, sseReply.Body.String(), `"content":"hi"`)
	assert.Contains(t, sseReply.Body.String(), "data: [DONE]")
	assert.NotContains(t, sseReply.Body.String(), `"total_tokens":3000`)

	captured := h.upstream.captured()
	require.Len(t, captured, 2)
	for _, upstream := range captured {
		assert.Equal(t, http.MethodPost, upstream.Method)
		assert.Equal(t, "/v1/chat/completions", upstream.URL)
		assert.Equal(t, "Bearer fake-upstream-key", upstream.Header.Get("Authorization"))
		for _, header := range []string{"X-Api-Key", "X-Resource-Instance-Proof", "Idempotency-Key", "Cookie"} {
			assert.Empty(t, upstream.Header.Get(header))
		}
	}
	assert.Contains(t, captured[1].Body, `"include_usage":true`)

	for _, test := range []struct {
		name   string
		change func(jwt.MapClaims)
	}{
		{"wrong audience", func(claims jwt.MapClaims) { claims["aud"] = "tool-sandbox" }},
		{"multiple audiences", func(claims jwt.MapClaims) { claims["aud"] = []string{"model-relay", "tool-sandbox"} }},
		{"wrong issuer", func(claims jwt.MapClaims) { claims["iss"] = "untrusted" }},
		{"wrong environment", func(claims jwt.MapClaims) { claims["environment"] = "other" }},
		{"wrong product", func(claims jwt.MapClaims) { claims["product_id"] = "other" }},
		{"wrong instance key", func(claims jwt.MapClaims) { claims["instance_id"] = "instance-2" }},
		{"expired", func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Second).Unix() }},
		{"future validity", func(claims jwt.MapClaims) { claims["nbf"] = time.Now().Add(time.Minute).Unix() }},
		{"missing payer", func(claims jwt.MapClaims) { delete(claims, "payer_id") }},
		{"missing organization workspace", func(claims jwt.MapClaims) { delete(claims, "workspace_id") }},
		{"missing token expiry", func(claims jwt.MapClaims) { delete(claims, "exp") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.claims()
			test.change(claims)
			req := fixture.request(t, "denied", relayTestBody, claims)
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, req)
			assert.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
		})
	}

	signedRequest := fixture.request(t, "proof-bound", relayTestBody, fixture.claims())
	signedRequest.Header.Set("Idempotency-Key", "different-key")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, signedRequest)
	assert.Equal(t, http.StatusUnauthorized, response.Code)

	changedBody := fixture.request(t, "body-bound", relayTestBody, fixture.claims())
	changedBody.Body = io.NopCloser(strings.NewReader(strings.Replace(relayTestBody, "hello", "Hello", 1)))
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, changedBody)
	assert.Equal(t, http.StatusUnauthorized, response.Code)

	req := fixture.request(t, "new-api-key", relayTestBody, fixture.claims())
	req.Header.Set("Authorization", "Bearer "+relayTestToken)
	response = httptest.NewRecorder()
	engine.ServeHTTP(response, req)
	assert.Equal(t, http.StatusUnauthorized, response.Code)

	limited := strings.Replace(relayTestBody, `"max_tokens":32`, `"max_tokens":256`, 1)
	assert.Equal(t, http.StatusBadRequest, fixture.post(t, engine, "output-limit", limited).Code)
	otherModel := strings.Replace(relayTestBody, relayTestModel, "other-model", 1)
	assert.Equal(t, http.StatusForbidden, fixture.post(t, engine, "model-scope", otherModel).Code)

	fixture.writeTrust(t, 2, []string{"sample-access"})
	assert.Equal(t, http.StatusUnauthorized, fixture.post(t, fixture.router(t), "revoked", relayTestBody).Code)
	require.Len(t, h.upstream.captured(), 2)

	ordinary := h.post(t, "/v1/chat/completions", relayTestBody)
	require.Equal(t, http.StatusOK, ordinary.status, ordinary.body)
	assert.Positive(t, ordinary.quota)
}

func TestProductModelUsageOutbox(t *testing.T) {
	h := newRelayHarness(t)
	require.NoError(t, model.DB.AutoMigrate(&model.ProductModelCall{}, &model.ProductModelAllocation{}))
	channel := h.install(t, h.newChannel(constant.ChannelTypeOpenAI, "fake-upstream-key"))
	var seenMu sync.Mutex
	seen := make(map[string]map[string]any)
	received := 0
	batches := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/internal/v1/usage:ingest", r.URL.Path)
		assert.Equal(t, "Bearer fixture-metering-key", r.Header.Get("Authorization"))
		var payload struct {
			Events []map[string]any `json:"events"`
		}
		if !assert.NoError(t, common.DecodeJson(r.Body, &payload)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		seenMu.Lock()
		defer seenMu.Unlock()
		batches++
		var ids []string
		for _, event := range payload.Events {
			id, _ := event["eventId"].(string)
			assert.NotEmpty(t, id)
			assert.Equal(t, event["attemptId"], id)
			assert.NotContains(t, event, "requestHash")
			if old, exists := seen[id]; exists {
				assert.Equal(t, old, event)
			}
			seen[id] = event
			received++
			ids = append(ids, id)
		}
		if batches == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // Events were accepted before the acknowledgement was lost.
			return
		}
		ack, _ := common.Marshal(map[string]any{"acceptedEventIds": ids})
		_, _ = w.Write(ack)
	}))
	t.Cleanup(receiver.Close)

	endpoint := receiver.URL + "/internal/v1/usage:ingest"
	fixture := newProductRouteFixture(t, channel.Id, endpoint, 4)
	engine := fixture.router(t)
	h.upstream.respond = func(w http.ResponseWriter, attempt int, request capturedRequest) {
		w.Header().Set("X-Request-Id", fmt.Sprintf("provider-%d", attempt))
		switch attempt {
		case 3:
			w.Header().Set("Content-Type", "text/event-stream")
			frame, _, _ := strings.Cut(chatStream, "\n\n")
			_, _ = io.WriteString(w, frame+"\n\n")
		case 4:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"type":"rate_limit","message":"busy"}}`)
		default:
			writeChat(w, request)
		}
	}

	jsonResponse := fixture.post(t, engine, "json", relayTestBody)
	require.Equal(t, http.StatusOK, jsonResponse.Code, jsonResponse.Body.String())
	callID := jsonResponse.Header().Get("X-Product-Call-Id")
	attemptID := jsonResponse.Header().Get("X-Product-Attempt-Id")
	require.NotEmpty(t, callID)
	require.NotEmpty(t, attemptID)
	require.Len(t, h.upstream.captured(), 1)
	assert.Equal(t, attemptID, h.upstream.captured()[0].Header.Get("X-Client-Request-Id"))

	duplicate := fixture.post(t, engine, "json", relayTestBody)
	require.Equal(t, http.StatusOK, duplicate.Code, duplicate.Body.String())
	assert.Equal(t, attemptID, duplicate.Header().Get("X-Product-Attempt-Id"))
	assert.Contains(t, duplicate.Body.String(), `"status":"confirmed"`)
	assert.Contains(t, duplicate.Body.String(), `"total_tokens":3000`)
	assert.Equal(t, http.StatusConflict, fixture.post(t, engine, "json", strings.Replace(relayTestBody, "hello", "different", 1)).Code)

	rotated := fixture.claims()
	rotated["payer_id"] = "other-payer"
	conflict := httptest.NewRecorder()
	engine.ServeHTTP(conflict, fixture.request(t, "json", relayTestBody, rotated))
	assert.Equal(t, http.StatusConflict, conflict.Code)

	streamBody := strings.TrimSuffix(relayTestBody, "}") + `,"stream":true}`
	stream := fixture.post(t, engine, "sse", streamBody)
	require.Equal(t, http.StatusOK, stream.Code, stream.Body.String())
	assert.Contains(t, stream.Body.String(), "data: [DONE]")
	assert.Contains(t, stream.Body.String(), `"total_tokens":3000`)
	streamAttempt := stream.Header().Get("X-Product-Attempt-Id")

	cut := fixture.post(t, engine, "cut", streamBody)
	assert.Contains(t, cut.Body.String(), "Upstream stream ended before completion")
	cutAttempt := cut.Header().Get("X-Product-Attempt-Id")
	pending := fixture.post(t, engine, "cut", streamBody)
	require.Equal(t, http.StatusOK, pending.Code)
	assert.Equal(t, cutAttempt, pending.Header().Get("X-Product-Attempt-Id"))
	assert.Contains(t, pending.Body.String(), `"status":"pending_review"`)
	assert.NotContains(t, pending.Body.String(), `"usage"`)

	rejected := fixture.post(t, engine, "provider-rejected", relayTestBody)
	require.Equal(t, http.StatusTooManyRequests, rejected.Code)
	assert.Contains(t, fixture.post(t, engine, "provider-rejected", relayTestBody).Body.String(), `"status":"rejected"`)
	exhausted := fixture.post(t, engine, "no-admission", relayTestBody)
	assert.Equal(t, http.StatusTooManyRequests, exhausted.Code)
	assert.Contains(t, exhausted.Body.String(), "product_allocation_exhausted")
	require.Len(t, h.upstream.captured(), 4)

	var token model.Token
	require.NoError(t, model.DB.First(&token, h.tokenID).Error)
	assert.EqualValues(t, 100_000_000, token.RemainQuota)
	var user model.User
	require.NoError(t, model.DB.First(&user, h.userID).Error)
	assert.EqualValues(t, 100_000_000, user.Quota)
	assert.Zero(t, user.UsedQuota)
	seenMu.Lock()
	assert.Zero(t, batches)
	seenMu.Unlock()

	now := time.Now().Unix()
	_, won, err := model.BeginProductModelCall(t.Context(), model.ProductModelCall{
		CallID: "abandoned", AttemptID: "abandoned-attempt", ProductID: "sample-product", Environment: "test",
		ProductUserID: "sample-user", PayerID: "sample-payer", ReviewAfter: now - 1, State: model.ProductCallInFlight,
	}, "recovery-fixture-allocation", 1)
	require.NoError(t, err)
	require.True(t, won)

	reporter, err := service.NewProductUsageReporter(endpoint, "fixture-metering-key")
	require.NoError(t, err)
	require.ErrorContains(t, reporter.Flush(t.Context()), "503")
	require.NoError(t, model.DB.Model(&model.ProductModelCall{}).Where("deliver_after > ?", now).Update("deliver_after", now).Error)
	restartedReporter, err := service.NewProductUsageReporter(endpoint, "fixture-metering-key")
	require.NoError(t, err)
	require.NoError(t, restartedReporter.Flush(t.Context()))
	require.NoError(t, restartedReporter.Flush(t.Context()))

	seenMu.Lock()
	defer seenMu.Unlock()
	assert.Equal(t, 2, batches)
	assert.Equal(t, 8, received)
	require.Len(t, seen, 4)
	require.Contains(t, seen, attemptID)
	jsonUse := seen[attemptID]
	assert.Equal(t, callID, jsonUse["callId"])
	assert.Equal(t, "sample-payer", jsonUse["payerId"])
	assert.Equal(t, "organization", jsonUse["payerType"])
	assert.Equal(t, "sample-user", jsonUse["productUserId"])
	assert.Equal(t, "sample-workspace", jsonUse["workspaceId"])
	assert.Equal(t, "provider-1", jsonUse["providerRequestId"])
	assert.Equal(t, "chatcmpl-1", jsonUse["providerResponseId"])
	assert.Equal(t, map[string]any{"inputTokens": float64(1000), "outputTokens": float64(2000), "totalTokens": float64(3000)}, jsonUse["usage"])
	require.Contains(t, seen, streamAttempt)
	assert.Equal(t, jsonUse["usage"], seen[streamAttempt]["usage"])
	require.Contains(t, seen, cutAttempt)
	assert.Equal(t, "pending_review", seen[cutAttempt]["status"])
	assert.Equal(t, "provider-3", seen[cutAttempt]["providerRequestId"])
	assert.NotContains(t, seen[cutAttempt], "usage")
	assert.Equal(t, "pending_review", seen["abandoned-attempt"]["status"])
}

func TestProductModelReplayDuringProviderCall(t *testing.T) {
	h := newRelayHarness(t)
	require.NoError(t, model.DB.AutoMigrate(&model.ProductModelCall{}, &model.ProductModelAllocation{}))
	channel := h.install(t, h.newChannel(constant.ChannelTypeOpenAI, "fake-upstream-key"))
	fixture := newProductRouteFixture(t, channel.Id, "http://127.0.0.1:1/internal/v1/usage:ingest", 1)
	engine := fixture.router(t)
	started := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	h.upstream.respond = func(w http.ResponseWriter, attempt int, request capturedRequest) {
		if attempt == 1 {
			close(started)
			<-release
		}
		writeChat(w, request)
	}

	firstRequest := fixture.request(t, "same-call", relayTestBody, fixture.claims())
	first := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		engine.ServeHTTP(first, firstRequest)
	}()
	select {
	case <-started:
	case <-finished:
		t.Fatalf("call ended before reaching the provider: %d %s", first.Code, first.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("call did not reach the provider")
	}
	replay := fixture.post(t, engine, "same-call", relayTestBody)
	require.Equal(t, http.StatusOK, replay.Code, replay.Body.String())
	assert.Contains(t, replay.Body.String(), `"status":"in_flight"`)
	unblock()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("provider call did not finish")
	}
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	assert.Equal(t, first.Header().Get("X-Product-Attempt-Id"), replay.Header().Get("X-Product-Attempt-Id"))
	require.Len(t, h.upstream.captured(), 1)
}

type productRouteFixture struct {
	configPath  string
	trustPath   string
	signingKey  ed25519.PrivateKey
	instanceKey ed25519.PrivateKey
	otherKey    ed25519.PublicKey
	maxCalls    int64
}

func newProductRouteFixture(t *testing.T, channelID int, meteringURL string, maxCalls int64) productRouteFixture {
	t.Helper()
	_, signingKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, instanceKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	otherKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	dir := t.TempDir()
	f := productRouteFixture{
		configPath: filepath.Join(dir, "route.json"), trustPath: filepath.Join(dir, "trust.json"),
		signingKey: signingKey, instanceKey: instanceKey, otherKey: otherKey, maxCalls: maxCalls,
	}
	config, err := common.Marshal(map[string]any{
		"issuer": "test-resource", "audience": "model-relay", "environment": "test", "model": relayTestModel,
		"channel_id": channelID, "max_output_tokens": 64, "trust_file": f.trustPath,
		"metering_url": meteringURL,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, config, 0600))
	f.writeTrust(t, 1, nil)
	return f
}

func (f productRouteFixture) writeTrust(t *testing.T, version int, revoked []string) {
	t.Helper()
	encoding := base64.RawURLEncoding
	data, err := common.Marshal(map[string]any{
		"version": version, "signing_keys": map[string]string{"test-key": encoding.EncodeToString(f.signingKey.Public().(ed25519.PublicKey))},
		"instances": map[string]map[string]string{"sample-product": {
			"instance-1": encoding.EncodeToString(f.instanceKey.Public().(ed25519.PublicKey)),
			"instance-2": encoding.EncodeToString(f.otherKey),
		}},
		"revoked_access_ids": revoked,
		"allocations":        map[string]map[string]int64{"sample-product": {"sample-allocation": f.maxCalls}},
	})
	require.NoError(t, err)
	temp := f.trustPath + ".tmp"
	require.NoError(t, os.WriteFile(temp, data, 0600))
	require.NoError(t, os.Rename(temp, f.trustPath))
}

func (f productRouteFixture) claims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": "test-resource", "aud": "model-relay", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
		"sub": "sample-user", "access_id": "sample-access", "product_id": "sample-product",
		"allocation_id": "sample-allocation", "payer_type": "organization",
		"environment": "test", "instance_id": "instance-1", "payer_id": "sample-payer", "workspace_id": "sample-workspace", "model": relayTestModel,
	}
}

func (f productRouteFixture) request(t *testing.T, key, body string, claims jwt.MapClaims) *http.Request {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "test-key"
	token.Header["typ"] = "resource+jwt"
	signed, err := token.SignedString(f.signingKey)
	require.NoError(t, err)
	proof := fmt.Sprintf("product-model-relay-v1\nPOST\n%s\n%x\n%s\n%x",
		controller.ProductChatPath, sha256.Sum256([]byte(signed)), key, sha256.Sum256([]byte(body)))
	req := httptest.NewRequest(http.MethodPost, controller.ProductChatPath+"?key=fixture-query", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("X-Resource-Instance-Proof", base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.instanceKey, []byte(proof))))
	req.Header.Set("X-Api-Key", "other-credential")
	req.Header.Set("Cookie", "session=fixture-cookie")
	return req
}

func (f productRouteFixture) router(t *testing.T) *gin.Engine {
	t.Helper()
	product, err := controller.LoadProductRelay(f.configPath, "fixture-metering-key")
	require.NoError(t, err)
	engine := gin.New()
	SetRelayRouter(engine)
	SetProductRelayRouter(engine, product)
	return engine
}

func (f productRouteFixture) post(t *testing.T, engine *gin.Engine, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, f.request(t, key, body, f.claims()))
	return response
}
