package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	thingscloud "github.com/arthursoares/things-cloud-sdk"
	_ "modernc.org/sqlite"
)

// ---------------------------------------------------------------------------
// OAuth 2.1 types
// ---------------------------------------------------------------------------

type OAuthServer struct {
	um            *UserManager
	publicBaseURL string
	jwtSecret     []byte
	credentialKey []byte
	clients       map[string]*OAuthClient  // client_id -> client
	authCodes     map[string]*AuthCode     // code -> auth code data
	refreshTokens map[string]*RefreshToken // token -> refresh data
	credentials   map[string]string        // email -> password (from successful authorizations)
	db            *sql.DB                  // SQLite database
	mu            sync.RWMutex
}

type OAuthClient struct {
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	ClientName    string    `json:"client_name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	GrantTypes    []string  `json:"grant_types"`
	ResponseTypes []string  `json:"response_types"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

type AuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	Email         string
	Password      string
	CodeChallenge string
	ExpiresAt     time.Time
}

type RefreshToken struct {
	Token     string
	Email     string
	Password  string
	ClientID  string
	ExpiresAt time.Time
}

// NewOAuthServer creates a new OAuth server, loading persisted state from dataDir.
// JWT secret priority: JWT_SECRET env var > DB > generate new.
func NewOAuthServer(um *UserManager, dataDir string) *OAuthServer {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("Failed to create data directory %s: %v", dataDir, err)
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		log.Fatalf("Failed to secure data directory %s: %v", dataDir, err)
	}

	dbPath := filepath.Join(dataDir, "oauth.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		log.Fatalf("Failed to open SQLite database: %v", err)
	}

	// Create tables
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS clients (
			client_id TEXT PRIMARY KEY, client_secret TEXT DEFAULT '',
			client_name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
			grant_types TEXT NOT NULL, response_types TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY, email TEXT NOT NULL, password TEXT NOT NULL,
			client_id TEXT NOT NULL, expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS credentials (email TEXT PRIMARY KEY, password TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS diagnoses (
			token TEXT PRIMARY KEY, report_json TEXT NOT NULL,
			email TEXT NOT NULL, created_at TEXT NOT NULL
		)`,
	} {
		if _, err := db.Exec(ddl); err != nil {
			log.Fatalf("Failed to create table: %v", err)
		}
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		log.Fatalf("Failed to secure OAuth database: %v", err)
	}

	publicBaseURL := ""
	if raw := os.Getenv("PUBLIC_BASE_URL"); strings.TrimSpace(raw) != "" {
		var err error
		publicBaseURL, err = validatePublicBaseURL(raw)
		if err != nil {
			log.Fatalf("Invalid PUBLIC_BASE_URL: %v", err)
		}
	}
	o := &OAuthServer{
		um:            um,
		publicBaseURL: publicBaseURL,
		db:            db,
		clients:       make(map[string]*OAuthClient),
		authCodes:     make(map[string]*AuthCode),
		refreshTokens: make(map[string]*RefreshToken),
		credentials:   make(map[string]string),
	}
	credentialKey, err := loadOrCreateCredentialKey(db, dataDir)
	if err != nil {
		log.Fatalf("Failed to initialize OAuth credential encryption: %v", err)
	}
	o.credentialKey = credentialKey

	// Load JWT secret: env > DB > generate
	if envSecret := os.Getenv("JWT_SECRET"); envSecret != "" {
		if len(envSecret) < 32 {
			log.Fatalf("JWT_SECRET must contain at least 32 characters")
		}
		o.jwtSecret = []byte(envSecret)
	} else {
		var dbSecret string
		if err := db.QueryRow(`SELECT value FROM kv WHERE key='jwt_secret'`).Scan(&dbSecret); err == nil {
			if secret, err := base64.RawURLEncoding.DecodeString(dbSecret); err == nil {
				if len(secret) >= 32 {
					o.jwtSecret = secret
				}
			}
		}
	}
	if len(o.jwtSecret) == 0 {
		o.jwtSecret = make([]byte, 32)
		if _, err := rand.Read(o.jwtSecret); err != nil {
			log.Fatalf("Failed to generate JWT secret: %v", err)
		}
		log.Printf("Generated new JWT secret (will be persisted)")
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO kv (key, value) VALUES ('jwt_secret', ?)`,
		base64.RawURLEncoding.EncodeToString(o.jwtSecret)); err != nil {
		log.Fatalf("Failed to persist JWT secret: %v", err)
	}

	// Load clients
	rows, err := db.Query(`SELECT client_id, client_secret, client_name, redirect_uris, grant_types, response_types, created_at FROM clients`)
	if err == nil {
		for rows.Next() {
			var c OAuthClient
			var redirectURIs, grantTypes, responseTypes, createdAt string
			if err := rows.Scan(&c.ClientID, &c.ClientSecret, &c.ClientName, &redirectURIs, &grantTypes, &responseTypes, &createdAt); err != nil {
				continue
			}
			json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs)
			json.Unmarshal([]byte(grantTypes), &c.GrantTypes)
			json.Unmarshal([]byte(responseTypes), &c.ResponseTypes)
			c.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
			o.clients[c.ClientID] = &c
		}
		rows.Close()
	}

	// Load refresh tokens (skip expired)
	now := time.Now()
	rows2, err := db.Query(`SELECT token, email, password, client_id, expires_at FROM refresh_tokens`)
	if err == nil {
		type refreshMigration struct{ oldToken, newToken, encrypted string }
		var migrations []refreshMigration
		for rows2.Next() {
			var rt RefreshToken
			var storedToken string
			var storedPassword string
			var expiresAt string
			if err := rows2.Scan(&storedToken, &rt.Email, &storedPassword, &rt.ClientID, &expiresAt); err != nil {
				continue
			}
			tokenKey, legacyToken := normalizeStoredRefreshToken(storedToken)
			rt.Token = tokenKey
			password, legacy, err := o.decryptPassword(storedPassword)
			if err != nil {
				log.Fatalf("Failed to decrypt persisted refresh credential; verify CREDENTIALS_SECRET or credentials.key")
			}
			rt.Password = password
			encryptedPassword := storedPassword
			if legacy {
				encryptedPassword, err = o.encryptPassword(password)
				if err != nil {
					log.Fatalf("Failed to migrate refresh credential encryption: %v", err)
				}
			}
			if legacy || legacyToken {
				migrations = append(migrations, refreshMigration{storedToken, tokenKey, encryptedPassword})
			}
			rt.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
			if now.After(rt.ExpiresAt) {
				continue
			}
			o.refreshTokens[tokenKey] = &rt
		}
		rows2.Close()
		for _, migration := range migrations {
			if _, err := db.Exec(`UPDATE refresh_tokens SET token=?, password=? WHERE token=?`, migration.newToken, migration.encrypted, migration.oldToken); err != nil {
				log.Fatalf("Failed to migrate refresh credential: %v", err)
			}
		}
	}
	// Clean expired from DB
	db.Exec(`DELETE FROM refresh_tokens WHERE expires_at < ?`, now.Format(time.RFC3339))

	// Load credentials
	rows3, err := db.Query(`SELECT email, password FROM credentials`)
	if err == nil {
		type credentialMigration struct{ email, encrypted string }
		var migrations []credentialMigration
		for rows3.Next() {
			var email, storedPassword string
			if err := rows3.Scan(&email, &storedPassword); err != nil {
				continue
			}
			password, legacy, err := o.decryptPassword(storedPassword)
			if err != nil {
				log.Fatalf("Failed to decrypt persisted credential; verify CREDENTIALS_SECRET or credentials.key")
			}
			o.credentials[email] = password
			if legacy {
				encrypted, err := o.encryptPassword(password)
				if err != nil {
					log.Fatalf("Failed to migrate credential encryption: %v", err)
				}
				migrations = append(migrations, credentialMigration{email, encrypted})
			}
		}
		rows3.Close()
		for _, migration := range migrations {
			if _, err := db.Exec(`UPDATE credentials SET password=? WHERE email=?`, migration.encrypted, migration.email); err != nil {
				log.Fatalf("Failed to migrate credential: %v", err)
			}
		}
	}

	log.Printf("Loaded OAuth state: %d clients, %d refresh tokens, %d users",
		len(o.clients), len(o.refreshTokens), len(o.credentials))

	return o
}

const encryptedPasswordPrefix = "enc:v1:"
const refreshTokenHashPrefix = "sha256:"

var credentialAAD = []byte("things-cloud-mcp/oauth-password/v1")

func loadOrCreateCredentialKey(db *sql.DB, dataDir string) ([]byte, error) {
	if envSecret := os.Getenv("CREDENTIALS_SECRET"); envSecret != "" {
		if len(envSecret) < 32 {
			return nil, fmt.Errorf("CREDENTIALS_SECRET must contain at least 32 characters")
		}
		digest := sha256.Sum256([]byte(envSecret))
		return digest[:], nil
	}

	keyPath := filepath.Join(dataDir, "credentials.key")
	if encoded, err := os.ReadFile(keyPath); err == nil {
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid credential key file %s", keyPath)
		}
		if err := os.Chmod(keyPath, 0600); err != nil {
			return nil, fmt.Errorf("secure credential key permissions: %w", err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read credential key: %w", err)
	}

	var encryptedRows int
	if err := db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM credentials WHERE password LIKE 'enc:v1:%') +
		(SELECT COUNT(*) FROM refresh_tokens WHERE password LIKE 'enc:v1:%')`).Scan(&encryptedRows); err != nil {
		return nil, fmt.Errorf("check encrypted credentials: %w", err)
	}
	if encryptedRows > 0 {
		return nil, fmt.Errorf("credentials.key is missing while encrypted credentials exist; restore the key or set CREDENTIALS_SECRET")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate credential key: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write credential key: %w", err)
	}
	return key, nil
}

func (o *OAuthServer) passwordAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(o.credentialKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (o *OAuthServer) encryptPassword(password string) (string, error) {
	aead, err := o.passwordAEAD()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, []byte(password), credentialAAD)
	payload := append(nonce, sealed...)
	return encryptedPasswordPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// decryptPassword returns legacy=true for a plaintext row so startup can
// transparently migrate databases created by older releases.
func (o *OAuthServer) decryptPassword(stored string) (password string, legacy bool, err error) {
	if !strings.HasPrefix(stored, encryptedPasswordPrefix) {
		return stored, true, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, encryptedPasswordPrefix))
	if err != nil {
		return "", false, fmt.Errorf("decode encrypted credential: %w", err)
	}
	aead, err := o.passwordAEAD()
	if err != nil {
		return "", false, err
	}
	if len(payload) < aead.NonceSize() {
		return "", false, fmt.Errorf("encrypted credential is truncated")
	}
	nonce, ciphertext := payload[:aead.NonceSize()], payload[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, credentialAAD)
	if err != nil {
		return "", false, fmt.Errorf("decrypt credential: %w", err)
	}
	return string(plaintext), false, nil
}

func (o *OAuthServer) persistCredential(email, password string) error {
	encrypted, err := o.encryptPassword(password)
	if err != nil {
		return err
	}
	_, err = o.db.Exec(`INSERT OR REPLACE INTO credentials (email, password) VALUES (?, ?)`, email, encrypted)
	return err
}

func (o *OAuthServer) persistRefreshToken(rt *RefreshToken) error {
	encrypted, err := o.encryptPassword(rt.Password)
	if err != nil {
		return err
	}
	_, err = o.db.Exec(`INSERT INTO refresh_tokens VALUES(?,?,?,?,?)`,
		refreshTokenKey(rt.Token), rt.Email, encrypted, rt.ClientID, rt.ExpiresAt.Format(time.RFC3339))
	return err
}

func refreshTokenKey(token string) string {
	digest := sha256.Sum256([]byte(token))
	return refreshTokenHashPrefix + fmt.Sprintf("%x", digest[:])
}

func normalizeStoredRefreshToken(stored string) (key string, legacy bool) {
	if strings.HasPrefix(stored, refreshTokenHashPrefix) {
		return stored, false
	}
	return refreshTokenKey(stored), true
}

func (o *OAuthServer) rotateRefreshToken(oldToken string, next *RefreshToken) error {
	encryptedPassword, err := o.encryptPassword(next.Password)
	if err != nil {
		return err
	}
	tx, err := o.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM refresh_tokens WHERE token=?`, refreshTokenKey(oldToken)); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO credentials (email, password) VALUES (?, ?)`, next.Email, encryptedPassword); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO refresh_tokens VALUES(?,?,?,?,?)`,
		refreshTokenKey(next.Token), next.Email, encryptedPassword, next.ClientID, next.ExpiresAt.Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secure random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func getBaseURL(r *http.Request) string {
	if configured := strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")); configured != "" {
		return strings.TrimRight(configured, "/")
	}
	return ""
}

func requestBaseURL(w http.ResponseWriter, r *http.Request) (string, bool) {
	base := getBaseURL(r)
	if base == "" {
		http.Error(w, "server base URL is not configured", http.StatusInternalServerError)
		return "", false
	}
	return base, true
}

func validatePublicBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("PUBLIC_BASE_URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("PUBLIC_BASE_URL must be an absolute URL without credentials, query, or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHostname(u.Hostname())) {
		return "", fmt.Errorf("PUBLIC_BASE_URL must use https except for loopback development")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("PUBLIC_BASE_URL must not contain a path")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func isLoopbackHostname(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("redirect URI must be absolute and must not contain credentials or a fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHostname(u.Hostname())) {
		return fmt.Errorf("redirect URI must use https except for loopback clients")
	}
	return nil
}

func validateCodeChallenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

func verifyPKCE(codeVerifier, codeChallenge string) bool {
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return hmac.Equal([]byte(computed), []byte(codeChallenge))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, errCode, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

// ---------------------------------------------------------------------------
// Minimal JWT HS256 implementation
// ---------------------------------------------------------------------------

func (o *OAuthServer) createJWT(claims map[string]any) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, o.jwtSecret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

func (o *OAuthServer) parseJWT(tokenStr string) (map[string]any, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, o.jwtSecret)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid JWT signature")
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}

	// Access tokens must always have a valid expiry.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("JWT is missing expiration")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("JWT expired")
	}

	return claims, nil
}

// ResolveBearer validates a Bearer token and returns the user's ThingsMCP instance.
func (o *OAuthServer) ResolveBearer(token string) (string, string, error) {
	claims, err := o.parseJWT(token)
	if err != nil {
		return "", "", fmt.Errorf("invalid token: %w", err)
	}

	email, ok := claims["sub"].(string)
	if !ok || email == "" {
		return "", "", fmt.Errorf("invalid token: missing subject")
	}
	if o.publicBaseURL != "" {
		issuer, ok := claims["iss"].(string)
		if !ok || issuer != o.publicBaseURL {
			return "", "", fmt.Errorf("invalid token: issuer mismatch")
		}
	}
	if scope, ok := claims["scope"].(string); !ok || !strings.Contains(" "+scope+" ", " things:manage ") {
		return "", "", fmt.Errorf("invalid token: required scope is missing")
	}

	o.mu.RLock()
	password, ok := o.credentials[email]
	o.mu.RUnlock()
	if !ok {
		return "", "", fmt.Errorf("no credentials found for user")
	}

	return email, password, nil
}

// ---------------------------------------------------------------------------
// Discovery endpoints
// ---------------------------------------------------------------------------

func (o *OAuthServer) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base, ok := requestBaseURL(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 base,
		"authorization_servers":    []string{base},
		"scopes_supported":         []string{"things:manage"},
		"bearer_methods_supported": []string{"header"},
	})
}

func (o *OAuthServer) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base, ok := requestBaseURL(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"registration_endpoint":                 base + "/register",
		"scopes_supported":                      []string{"things:manage"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// ---------------------------------------------------------------------------
// Dynamic client registration
// ---------------------------------------------------------------------------

func (o *OAuthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		ClientName    string   `json:"client_name"`
		RedirectURIs  []string `json:"redirect_uris"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}

	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "redirect_uris is required")
		return
	}
	for _, redirectURI := range req.RedirectURIs {
		if err := validateRedirectURI(redirectURI); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	if req.ClientName == "" {
		req.ClientName = "Unknown Client"
	}
	if len(req.ClientName) > 128 {
		writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name is too long")
		return
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	for _, grantType := range req.GrantTypes {
		if grantType != "authorization_code" && grantType != "refresh_token" {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type")
			return
		}
	}
	for _, responseType := range req.ResponseTypes {
		if responseType != "code" {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response type")
			return
		}
	}

	clientID, err := randomString(24)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to create client identifier")
		return
	}

	client := &OAuthClient{
		ClientID:      clientID,
		ClientName:    req.ClientName,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
		CreatedAt:     time.Now(),
	}

	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	grantTypesJSON, _ := json.Marshal(client.GrantTypes)
	responseTypesJSON, _ := json.Marshal(client.ResponseTypes)
	if _, err := o.db.Exec(`INSERT INTO clients VALUES(?,?,?,?,?,?,?)`,
		clientID, client.ClientSecret, client.ClientName,
		string(redirectURIsJSON), string(grantTypesJSON), string(responseTypesJSON),
		client.CreatedAt.Format(time.RFC3339)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to register client")
		return
	}

	o.mu.Lock()
	o.clients[clientID] = client
	o.mu.Unlock()

	log.Printf("OAuth: registered client %q", req.ClientName)

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":      clientID,
		"client_name":    req.ClientName,
		"redirect_uris":  req.RedirectURIs,
		"grant_types":    req.GrantTypes,
		"response_types": req.ResponseTypes,
	})
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

func (o *OAuthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	o.pruneExpiredAuthCodes(time.Now())
	switch r.Method {
	case http.MethodGet:
		o.handleAuthorizeGet(w, r)
	case http.MethodPost:
		o.handleAuthorizePost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (o *OAuthServer) pruneExpiredAuthCodes(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for code, authCode := range o.authCodes {
		if now.After(authCode.ExpiresAt) {
			delete(o.authCodes, code)
		}
	}
}

func (o *OAuthServer) validateAuthorizationRequest(q url.Values) (*OAuthClient, error) {
	if q.Get("response_type") != "code" {
		return nil, fmt.Errorf("unsupported response_type")
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" || q.Get("state") == "" {
		return nil, fmt.Errorf("missing required authorization parameters")
	}
	if q.Get("code_challenge_method") != "S256" || !validateCodeChallenge(q.Get("code_challenge")) {
		return nil, fmt.Errorf("valid S256 PKCE challenge required")
	}

	o.mu.RLock()
	client, ok := o.clients[clientID]
	o.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown client_id")
	}
	for _, allowed := range client.RedirectURIs {
		if allowed == redirectURI {
			return client, nil
		}
	}
	return nil, fmt.Errorf("invalid redirect_uri")
}

func (o *OAuthServer) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := o.validateAuthorizationRequest(q)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	o.setAuthorizationFormCSP(w, q.Get("redirect_uri"))
	o.renderLoginPage(w, client.ClientName, "", q.Encode())
}

func (o *OAuthServer) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Query params come from the URL; form values from POST body
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	client, err := o.validateAuthorizationRequest(q)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	o.setAuthorizationFormCSP(w, redirectURI)

	email := r.PostFormValue("email")
	password := r.PostFormValue("password")

	if email == "" || password == "" {
		o.renderLoginPage(w, client.ClientName, "Email and password are required.", q.Encode())
		return
	}
	if !o.um.emailAllowed(email) {
		o.renderLoginPage(w, client.ClientName, "This account is not allowed on this server.", q.Encode())
		return
	}

	// Verify Things Cloud credentials
	var opts []thingscloud.ClientOption
	if proxy := o.um.proxyForEmail(email); proxy != nil {
		opts = append(opts, thingscloud.WithProxy(proxy))
	}
	c := thingscloud.New(thingscloud.APIEndpoint, email, password, opts...)
	if _, err := c.Verify(); err != nil {
		o.renderLoginPage(w, client.ClientName, "Invalid Things Cloud credentials.", q.Encode())
		return
	}

	// Generate auth code
	code, err := randomString(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to create authorization code")
		return
	}
	authCode := &AuthCode{
		Code:          code,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Email:         email,
		Password:      password,
		CodeChallenge: codeChallenge,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	o.mu.Lock()
	o.authCodes[code] = authCode
	o.mu.Unlock()

	log.Printf("OAuth: authorization code issued")

	// Redirect to client
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to create redirect")
		return
	}
	values := redirect.Query()
	values.Set("code", code)
	values.Set("state", state)
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (o *OAuthServer) setAuthorizationFormCSP(w http.ResponseWriter, redirectURI string) {
	formActions := []string{"'self'"}
	if o.publicBaseURL != "" {
		formActions = append(formActions, o.publicBaseURL)
	}
	if redirect, err := url.Parse(redirectURI); err == nil && redirect.Scheme != "" && redirect.Host != "" {
		formActions = append(formActions, redirect.Scheme+"://"+redirect.Host)
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy(formActions...))
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

func (o *OAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	o.pruneExpiredAuthCodes(time.Now())

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	grantType := r.PostFormValue("grant_type")
	switch grantType {
	case "authorization_code":
		o.handleAuthCodeGrant(w, r)
	case "refresh_token":
		o.handleRefreshTokenGrant(w, r)
	default:
		writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

func (o *OAuthServer) handleAuthCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("code")
	clientID := r.PostFormValue("client_id")
	redirectURI := r.PostFormValue("redirect_uri")
	codeVerifier := r.PostFormValue("code_verifier")

	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "missing required parameters: code, client_id, redirect_uri, code_verifier")
		return
	}

	o.mu.Lock()
	ac, ok := o.authCodes[code]
	if !ok {
		o.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "unknown authorization code")
		return
	}
	if time.Now().After(ac.ExpiresAt) {
		delete(o.authCodes, code)
		o.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if ac.ClientID != clientID {
		o.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if ac.RedirectURI != redirectURI {
		o.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Verify PKCE
	if !verifyPKCE(codeVerifier, ac.CodeChallenge) {
		o.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	email := ac.Email
	password := ac.Password
	delete(o.authCodes, code)
	o.mu.Unlock()

	if err := o.persistCredential(email, password); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to store credentials securely")
		return
	}

	// Generate tokens
	base, ok := requestBaseURL(w, r)
	if !ok {
		return
	}
	accessToken, err := o.createJWT(map[string]any{
		"sub":   email,
		"iss":   base,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "things:manage",
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to create access token")
		return
	}

	refreshTok, err := randomString(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to create refresh token")
		return
	}
	rt := &RefreshToken{
		Token:     refreshTok,
		Email:     email,
		Password:  password,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}
	if err := o.persistRefreshToken(rt); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to store refresh token securely")
		return
	}
	o.mu.Lock()
	o.credentials[email] = password
	o.refreshTokens[refreshTokenKey(refreshTok)] = rt
	o.mu.Unlock()

	log.Printf("OAuth: tokens issued")

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshTok,
		"scope":         "things:manage",
	})
}

func (o *OAuthServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshTok := r.PostFormValue("refresh_token")
	if refreshTok == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}

	refreshKey := refreshTokenKey(refreshTok)
	o.mu.Lock()
	rt, ok := o.refreshTokens[refreshKey]
	if !ok {
		o.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		delete(o.refreshTokens, refreshKey)
		o.mu.Unlock()
		o.db.Exec(`DELETE FROM refresh_tokens WHERE token=?`, refreshKey)
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	if !o.um.emailAllowed(rt.Email) {
		delete(o.refreshTokens, refreshKey)
		o.mu.Unlock()
		if _, err := o.db.Exec(`DELETE FROM refresh_tokens WHERE token=?`, refreshKey); err != nil {
			log.Printf("OAuth: failed to revoke disallowed refresh token")
		}
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "refresh token is no longer authorized")
		return
	}

	email := rt.Email
	password := rt.Password
	clientID := rt.ClientID

	// Reserve the one-time token in memory so concurrent refresh attempts cannot
	// both succeed. The database rotation below is transactional.
	delete(o.refreshTokens, refreshKey)
	o.mu.Unlock()
	restoreOldToken := func() {
		o.mu.Lock()
		o.refreshTokens[refreshKey] = rt
		o.mu.Unlock()
	}

	// Generate new tokens
	base, ok := requestBaseURL(w, r)
	if !ok {
		restoreOldToken()
		return
	}
	accessToken, err := o.createJWT(map[string]any{
		"sub":   email,
		"iss":   base,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "things:manage",
	})
	if err != nil {
		restoreOldToken()
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to create access token")
		return
	}

	newRefreshTok, err := randomString(32)
	if err != nil {
		restoreOldToken()
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to create refresh token")
		return
	}
	newRT := &RefreshToken{
		Token:     newRefreshTok,
		Email:     email,
		Password:  password,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := o.rotateRefreshToken(refreshTok, newRT); err != nil {
		restoreOldToken()
		writeJSONError(w, http.StatusInternalServerError, "server_error", "failed to store refresh token securely")
		return
	}
	o.mu.Lock()
	o.credentials[email] = password
	o.refreshTokens[refreshTokenKey(newRefreshTok)] = newRT
	o.mu.Unlock()

	log.Printf("OAuth: tokens refreshed")

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": newRefreshTok,
		"scope":         "things:manage",
	})
}

// ---------------------------------------------------------------------------
// Login page HTML
// ---------------------------------------------------------------------------

var authorizePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In - Things Cloud MCP</title>
<style>
` + sharedCSS + `
.auth-container{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:24px;
}
.auth-card{
  width:100%;
  max-width:380px;
  background:var(--surface);
  border:1px solid var(--divider);
  border-radius:var(--radius);
  padding:40px 32px;
  box-shadow:0 2px 12px rgba(0,0,0,0.06);
}
@media(prefers-color-scheme:dark){
  .auth-card{
    box-shadow:0 2px 12px rgba(0,0,0,0.2);
  }
}
.auth-icon{
  display:flex;
  justify-content:center;
  margin-bottom:24px;
}
.auth-icon svg{width:48px;height:48px}
.auth-title{
  font-size:20px;
  font-weight:700;
  text-align:center;
  letter-spacing:-0.3px;
  margin-bottom:6px;
}
.auth-subtitle{
  font-size:14px;
  color:var(--text-secondary);
  text-align:center;
  margin-bottom:28px;
}
.auth-error{
  background:#FFF2F2;
  color:#D70015;
  border:1px solid #FFD6D6;
  border-radius:var(--radius-sm);
  padding:10px 14px;
  font-size:13px;
  margin-bottom:20px;
  line-height:1.45;
}
@media(prefers-color-scheme:dark){
  .auth-error{
    background:#3A1C1C;
    color:#FF6B6B;
    border-color:#5A2C2C;
  }
}
.auth-field{
  margin-bottom:16px;
}
.auth-field label{
  display:block;
  font-size:13px;
  font-weight:600;
  margin-bottom:6px;
  color:var(--text);
}
.auth-field input{
  width:100%;
  padding:10px 14px;
  font-size:15px;
  border:1px solid var(--divider);
  border-radius:var(--radius-sm);
  background:var(--bg);
  color:var(--text);
  font-family:inherit;
  outline:none;
  transition:border-color 0.15s;
  box-sizing:border-box;
}
.auth-field input:focus{
  border-color:var(--blue);
}
.auth-btn{
  width:100%;
  padding:12px;
  font-size:15px;
  font-weight:600;
  color:#fff;
  background:var(--blue);
  border:none;
  border-radius:var(--radius-sm);
  cursor:pointer;
  font-family:inherit;
  transition:background 0.15s;
  margin-top:8px;
}
.auth-btn:hover{
  background:var(--blue-hover);
}
</style>
</head>
<body>
<div class="auth-container">
  <div class="auth-card">
    <div class="auth-icon">` + `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="48" height="48" fill="none">
  <path d="M50 46a11 11 0 0 0 0-22 11 11 0 0 0-1-.04 15 15 0 0 0-29-2A13 13 0 0 0 14 46h36z" fill="#1A7CF9"/>
  <polyline points="24,34 30,40 42,28" stroke="#fff" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>` + `</div>
    <div class="auth-title">Sign in with Things Cloud</div>
    <div class="auth-subtitle">{{subtitle}}</div>
    {{error}}
    <form method="POST" action="/authorize?{{query}}">
      <div class="auth-field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" required autocomplete="email" autofocus>
      </div>
      <div class="auth-field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autocomplete="current-password">
      </div>
      <button type="submit" class="auth-btn">Authorize</button>
    </form>
    <p style="margin-top:20px;font-size:11px;color:var(--text-secondary);text-align:center;line-height:1.5">Not affiliated with Cultured Code. Built through reverse engineering with <a href="https://github.com/arthursoares/things-cloud-sdk" target="_blank" rel="noopener" style="color:var(--blue);text-decoration:none">Things Cloud SDK</a>.</p>
  </div>
</div>
</body>
</html>`

func (o *OAuthServer) renderLoginPage(w http.ResponseWriter, clientName, errMsg, queryString string) {
	subtitle := "Authorize access to your tasks"
	if clientName != "" {
		subtitle = "<strong>" + htmlEscape(clientName) + "</strong> wants to access your tasks"
	}

	errorHTML := ""
	if errMsg != "" {
		errorHTML = `<div class="auth-error">` + htmlEscape(errMsg) + `</div>`
	}

	html := strings.Replace(
		strings.Replace(
			strings.Replace(authorizePageHTML, "{{subtitle}}", subtitle, 1),
			"{{error}}", errorHTML, 1),
		"{{query}}", queryString, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
