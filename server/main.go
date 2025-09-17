package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type Server struct {
	db         *sql.DB
	encryptKey []byte
}

type TokenRequest struct {
	XoxcToken  string `json:"xoxc_token"`
	XoxdCookie string `json:"xoxd_cookie"`
}

type OAuthTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type Response struct {
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

func main() {
	// Load .env file if it exists (ignore errors - file is optional)
	if err := godotenv.Load(); err == nil {
		log.Println("Loaded configuration from .env file")
	}

	server, err := NewServer()
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}
	defer server.db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/health", server.healthHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/tokens", server.tokensHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/oauth-tokens", server.oauthTokensHandler).Methods("POST", "OPTIONS")

	// Enable CORS for browser extension
	r.Use(corsMiddleware)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func NewServer() (*Server, error) {
	// Connect to database
	dbConfig, err := NewDatabaseConnection()
	if err != nil {
		return nil, err
	}

	// Load encryption key from environment variable
	var encryptKey []byte
	keyHex := os.Getenv("ENCRYPTION_KEY")
	
	if keyHex == "" {
		// Generate a new key and warn user
		encryptKey = make([]byte, 32)
		if _, err := rand.Read(encryptKey); err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %v", err)
		}
		keyHex = hex.EncodeToString(encryptKey)
		log.Printf("WARNING: No ENCRYPTION_KEY environment variable found!")
		log.Printf("Generated temporary key: %s", keyHex)
		log.Printf("Set ENCRYPTION_KEY=%s to persist tokens across restarts", keyHex)
	} else {
		// Use existing key from environment
		var err error
		encryptKey, err = hex.DecodeString(keyHex)
		if err != nil {
			// If hex decoding fails, treat as raw bytes (pad/truncate to 32 bytes)
			encryptKey = make([]byte, 32)
			keyBytes := []byte(keyHex)
			if len(keyBytes) >= 32 {
				copy(encryptKey, keyBytes[:32])
			} else {
				copy(encryptKey, keyBytes)
			}
			log.Printf("Using ENCRYPTION_KEY as raw bytes (not hex)")
		} else {
			log.Println("Using ENCRYPTION_KEY as hex-decoded bytes")
		}
	}

	server := &Server{
		db:         dbConfig.DB,
		encryptKey: encryptKey,
	}

	if err := dbConfig.RunMigrations(); err != nil {
		return nil, err
	}

	return server, nil
}



func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Message: "Server is healthy"})
}

func (s *Server) tokensHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "Invalid JSON request"})
		return
	}

	if req.XoxcToken == "" || req.XoxdCookie == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "Both xoxc_token and xoxd_cookie are required"})
		return
	}

	// Verify tokens with Slack API and get real user info
	userID, username, err := s.verifySlackTokens(req.XoxcToken, req.XoxdCookie)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Error: "Invalid Slack tokens: " + err.Error()})
		return
	}

	// Check if user already exists
	var existingUserID string
	err = s.db.QueryRow("SELECT user_id FROM slack_browser_tokens WHERE user_id = ?", userID).Scan(&existingUserID)

	if err == nil {
		// User already exists
		json.NewEncoder(w).Encode(Response{Message: fmt.Sprintf("already stored token for \"%s\"", username)})
		return
	} else if err != sql.ErrNoRows {
		// Database error
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "Database error"})
		return
	}

	// Encrypt tokens
	encryptedXoxc, err := s.encrypt(req.XoxcToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "Encryption error"})
		return
	}

	encryptedXoxd, err := s.encrypt(req.XoxdCookie)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "Encryption error"})
		return
	}

	// Insert new user
	_, err = s.db.Exec(
		"INSERT INTO slack_browser_tokens (user_id, username, encrypted_xoxc_token, encrypted_xoxd_cookie) VALUES (?, ?, ?, ?)",
		userID, username, encryptedXoxc, encryptedXoxd,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "Failed to store tokens"})
		return
	}

	json.NewEncoder(w).Encode(Response{Message: fmt.Sprintf("successfully stored token for \"%s\"", username)})
}

func (s *Server) oauthTokensHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req OAuthTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "Invalid JSON request"})
		return
	}

	if req.AccessToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Error: "access_token is required"})
		return
	}

	// Verify OAuth token with Slack API and get user info
	userID, username, err := s.verifyOAuthToken(req.AccessToken)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Error: "Invalid OAuth token: " + err.Error()})
		return
	}

	// Check if user already exists
	var existingUserID string
	err = s.db.QueryRow("SELECT user_id FROM slack_oauth_tokens WHERE user_id = ?", userID).Scan(&existingUserID)

	if err == nil {
		// User already exists, update tokens
		encryptedAccess, err := s.encrypt(req.AccessToken)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(Response{Error: "Encryption error"})
			return
		}

		var encryptedRefresh *string
		if req.RefreshToken != "" {
			encrypted, err := s.encrypt(req.RefreshToken)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(Response{Error: "Encryption error"})
				return
			}
			encryptedRefresh = &encrypted
		}

		// Update existing tokens
		_, err = s.db.Exec(
			`UPDATE slack_oauth_tokens SET 
				encrypted_access_token = ?, 
				encrypted_refresh_token = ?, 
				token_type = ?, 
				expires_in = ?, 
				scope = ?,
				updated_at = CURRENT_TIMESTAMP
			WHERE user_id = ?`,
			encryptedAccess, encryptedRefresh, req.TokenType, req.ExpiresIn, req.Scope, userID,
		)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(Response{Error: "Failed to update tokens"})
			return
		}

		json.NewEncoder(w).Encode(Response{Message: fmt.Sprintf("successfully updated OAuth token for \"%s\"", username)})
		return
	} else if err != sql.ErrNoRows {
		// Database error
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "Database error"})
		return
	}

	// Encrypt tokens for new user
	encryptedAccess, err := s.encrypt(req.AccessToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "Encryption error"})
		return
	}

	var encryptedRefresh *string
	if req.RefreshToken != "" {
		encrypted, err := s.encrypt(req.RefreshToken)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(Response{Error: "Encryption error"})
			return
		}
		encryptedRefresh = &encrypted
	}

	// Insert new user
	_, err = s.db.Exec(
		"INSERT INTO slack_oauth_tokens (user_id, username, encrypted_access_token, encrypted_refresh_token, token_type, expires_in, scope) VALUES (?, ?, ?, ?, ?, ?, ?)",
		userID, username, encryptedAccess, encryptedRefresh, req.TokenType, req.ExpiresIn, req.Scope,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{Error: "Failed to store OAuth tokens"})
		return
	}

	json.NewEncoder(w).Encode(Response{Message: fmt.Sprintf("successfully stored OAuth token for \"%s\"", username)})
}

type SlackAuthResponse struct {
	OK     bool   `json:"ok"`
	User   string `json:"user"`
	UserID string `json:"user_id"`
	Team   string `json:"team"`
}

type SlackUserResponse struct {
	OK   bool `json:"ok"`
	User struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
}

func (s *Server) verifySlackTokens(xoxcToken, xoxdCookie string) (userID, username string, err error) {
	// Make auth.test call to Slack API using xoxc token directly
	client := &http.Client{}

	data := url.Values{}
	data.Set("token", xoxcToken)

	req, err := http.NewRequest("POST", "https://slack.com/api/auth.test", strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cookieHeader := fmt.Sprintf("d=%s", xoxdCookie)
	req.Header.Set("Cookie", cookieHeader)
	cookiePreview := xoxdCookie
	if len(xoxdCookie) > 20 {
		cookiePreview = xoxdCookie[:20] + "..."
	}
	log.Printf("Sending cookie header: d=%s", cookiePreview)
	log.Printf("Sending token: %s...", xoxcToken[:20])
	
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to call auth.test: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
	 return "", "", fmt.Errorf("failed to read response body: %v", err)
	}
	
	log.Printf("Slack auth.test response status: %d", resp.StatusCode)
	log.Printf("Slack auth.test response body: %s", string(body))
	
	var authResp SlackAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", "", fmt.Errorf("failed to parse auth response: %v", err)
	}
	
	if !authResp.OK {
	return "", "", fmt.Errorf("auth.test failed - response: %s", string(body))
	}

	// We already have user info from auth.test, let's use that
	// The auth response has: user_id and user (username) fields
	log.Printf("Auth successful - User: %s, UserID: %s", authResp.User, authResp.UserID)
	
	return authResp.UserID, authResp.User, nil
}

func (s *Server) verifyOAuthToken(accessToken string) (userID, username string, err error) {
	// Make auth.test call to Slack API using OAuth token
	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to call auth.test: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %v", err)
	}

	log.Printf("OAuth auth.test response status: %d", resp.StatusCode)
	log.Printf("OAuth auth.test response body: %s", string(body))

	var authResp SlackAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", "", fmt.Errorf("failed to parse auth response: %v", err)
	}

	if !authResp.OK {
		return "", "", fmt.Errorf("OAuth auth.test failed - response: %s", string(body))
	}

	log.Printf("OAuth auth successful - User: %s, UserID: %s", authResp.User, authResp.UserID)
	return authResp.UserID, authResp.User, nil
}

func (s *Server) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.encryptKey)
	if err != nil {
		return "", err
	}

	// Create a new GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

func (s *Server) decrypt(ciphertext string) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.encryptKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
