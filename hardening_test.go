package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func validAuthorizationQuery() url.Values {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"client-1"},
		"redirect_uri":          {"https://client.example/callback"},
		"state":                 {"opaque-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
}

func TestAuthorizationValidationIsAppliedToPOST(t *testing.T) {
	o := &OAuthServer{
		um: NewUserManager(),
		clients: map[string]*OAuthClient{
			"client-1": {ClientID: "client-1", RedirectURIs: []string{"https://client.example/callback"}},
		},
	}

	q := validAuthorizationQuery()
	if _, err := o.validateAuthorizationRequest(q); err != nil {
		t.Fatalf("valid authorization request rejected: %v", err)
	}

	q.Set("redirect_uri", "https://attacker.example/callback")
	body := strings.NewReader("email=person%40example.com&password=not-sent")
	req := httptest.NewRequest(http.MethodPost, "/authorize?"+q.Encode(), body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	o.handleAuthorizePost(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid POST status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if len(o.authCodes) != 0 {
		t.Fatal("invalid POST created an authorization code")
	}
}

func TestAuthorizationValidationRejectsInvalidPKCE(t *testing.T) {
	o := &OAuthServer{clients: map[string]*OAuthClient{
		"client-1": {ClientID: "client-1", RedirectURIs: []string{"https://client.example/callback"}},
	}}
	q := validAuthorizationQuery()
	q.Set("code_challenge", "not-a-sha256-challenge")
	if _, err := o.validateAuthorizationRequest(q); err == nil {
		t.Fatal("invalid PKCE challenge was accepted")
	}
}

func TestRedirectURIValidation(t *testing.T) {
	for _, valid := range []string{
		"https://client.example/callback",
		"http://127.0.0.1:12345/callback",
		"http://localhost:12345/callback",
	} {
		if err := validateRedirectURI(valid); err != nil {
			t.Errorf("valid redirect %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"http://client.example/callback",
		"https://user:password@client.example/callback",
		"https://client.example/callback#fragment",
		"javascript:alert(1)",
	} {
		if err := validateRedirectURI(invalid); err == nil {
			t.Errorf("invalid redirect %q accepted", invalid)
		}
	}
}

func TestPublicBaseURLValidation(t *testing.T) {
	if got, err := validatePublicBaseURL("https://personal.example/"); err != nil || got != "https://personal.example" {
		t.Fatalf("valid public URL normalized to %q with error %v", got, err)
	}
	for _, invalid := range []string{"", "http://personal.example", "https://user:pass@personal.example", "https://personal.example/path"} {
		if _, err := validatePublicBaseURL(invalid); err == nil {
			t.Errorf("invalid public URL %q accepted", invalid)
		}
	}
}

func TestHardenedHTTPHandlerRejectsUnexpectedHost(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := hardenedHTTPHandler(next, "personal.example")

	req := httptest.NewRequest(http.MethodGet, "https://attacker.example/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusMisdirectedRequest {
		t.Fatalf("unexpected host status = %d, want %d", recorder.Code, http.StatusMisdirectedRequest)
	}
}

func TestHealthCheckDoesNotExposeApplication(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	})
	handler := hardenedHTTPHandler(next, "personal.example")

	req := httptest.NewRequest(http.MethodGet, "http://internal.fly/healthz", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("health check status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if nextCalled {
		t.Fatal("health check reached the application handler")
	}
}

func TestDiagnosticSharingIsOffByDefault(t *testing.T) {
	for _, value := range []string{"", "false", "0", "not-a-boolean"} {
		t.Setenv("ENABLE_DIAGNOSTIC_SHARING", value)
		if envEnabled("ENABLE_DIAGNOSTIC_SHARING") {
			t.Fatalf("diagnostic sharing enabled for %q", value)
		}
	}
	t.Setenv("ENABLE_DIAGNOSTIC_SHARING", "true")
	if !envEnabled("ENABLE_DIAGNOSTIC_SHARING") {
		t.Fatal("diagnostic sharing did not honor explicit opt-in")
	}
}

func TestCredentialSecretRequiresMinimumLength(t *testing.T) {
	t.Setenv("CREDENTIALS_SECRET", "too-short")
	if _, err := loadOrCreateCredentialKey(nil, ""); err == nil {
		t.Fatal("short credential secret was accepted")
	}
}

func TestUserManagerRestrictsAccount(t *testing.T) {
	um := NewUserManager()
	um.allowedEmail = "owner@example.com"
	if !um.emailAllowed("OWNER@example.com") {
		t.Fatal("configured account was rejected")
	}
	if um.emailAllowed("attacker@example.com") {
		t.Fatal("unconfigured account was accepted")
	}
}

func TestResolveBearerValidatesIssuerAndScope(t *testing.T) {
	o := &OAuthServer{
		publicBaseURL: "https://personal.example",
		jwtSecret:     []byte("0123456789abcdef0123456789abcdef"),
		credentials:   map[string]string{"owner@example.com": "test-password"},
	}
	claims := map[string]any{
		"sub": "owner@example.com", "iss": o.publicBaseURL,
		"scope": "things:manage", "exp": time.Now().Add(time.Hour).Unix(),
	}
	token, err := o.createJWT(claims)
	if err != nil {
		t.Fatalf("create valid token: %v", err)
	}
	if _, _, err := o.ResolveBearer(token); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	claims["iss"] = "https://attacker.example"
	token, _ = o.createJWT(claims)
	if _, _, err := o.ResolveBearer(token); err == nil {
		t.Fatal("token with wrong issuer was accepted")
	}

	claims["iss"] = o.publicBaseURL
	delete(claims, "scope")
	token, _ = o.createJWT(claims)
	if _, _, err := o.ResolveBearer(token); err == nil {
		t.Fatal("token without required scope was accepted")
	}
}

func TestExpiredAuthorizationCodesArePruned(t *testing.T) {
	o := &OAuthServer{authCodes: map[string]*AuthCode{
		"expired": {ExpiresAt: time.Now().Add(-time.Minute)},
		"current": {ExpiresAt: time.Now().Add(time.Minute)},
	}}
	o.pruneExpiredAuthCodes(time.Now())
	if _, ok := o.authCodes["expired"]; ok {
		t.Fatal("expired authorization code retained")
	}
	if _, ok := o.authCodes["current"]; !ok {
		t.Fatal("current authorization code removed")
	}
}

func TestLandingPageUsesConfiguredOrigin(t *testing.T) {
	t.Setenv("PUBLIC_BASE_URL", "https://personal.example")
	recorder := httptest.NewRecorder()
	handleLandingPage(recorder, httptest.NewRequest(http.MethodGet, "https://personal.example/", nil))
	body := recorder.Body.String()
	if strings.Contains(body, "https://thingscloudmcp.com") {
		t.Fatal("landing page retained the upstream service origin")
	}
	if !strings.Contains(body, "https://personal.example/mcp") {
		t.Fatal("landing page did not use the configured origin")
	}
}
