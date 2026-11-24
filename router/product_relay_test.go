package router

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/controller"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProductModelRoute(t *testing.T) {
	h := newRelayHarness(t)
	channel := h.newChannel(constant.ChannelTypeOpenAI, "fake-upstream-key")
	channel.HeaderOverride = common.GetPointer(`{"*":""}`)
	h.install(t, channel)
	fixture := newProductRouteFixture(t, channel.Id)
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
		{"wrong issuer", func(claims jwt.MapClaims) { claims["iss"] = "untrusted" }},
		{"wrong environment", func(claims jwt.MapClaims) { claims["environment"] = "other" }},
		{"wrong product", func(claims jwt.MapClaims) { claims["product_id"] = "other" }},
		{"wrong instance key", func(claims jwt.MapClaims) { claims["instance_id"] = "instance-2" }},
		{"expired", func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Second).Unix() }},
		{"future validity", func(claims jwt.MapClaims) { claims["nbf"] = time.Now().Add(time.Minute).Unix() }},
		{"missing payer", func(claims jwt.MapClaims) { delete(claims, "payer_id") }},
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

type productRouteFixture struct {
	configPath  string
	trustPath   string
	signingKey  ed25519.PrivateKey
	instanceKey ed25519.PrivateKey
	otherKey    ed25519.PublicKey
}

func newProductRouteFixture(t *testing.T, channelID int) productRouteFixture {
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
		signingKey: signingKey, instanceKey: instanceKey, otherKey: otherKey,
	}
	config, err := common.Marshal(map[string]any{
		"issuer": "test-resource", "audience": "model-relay", "environment": "test", "model": relayTestModel,
		"channel_id": channelID, "max_output_tokens": 64, "trust_file": f.trustPath,
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
	product, err := controller.LoadProductRelay(f.configPath)
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
