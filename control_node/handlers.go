package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

//go:embed resources/templates/dashboard.html
var dashboardHTML embed.FS

// statusHandler godoc
//
//	@Summary		Get the status of the control node
//	@Description	Get the status of the control node
//	@Tags			status
//	@Produce		plain
//	@Success		200	{string}	string	"Control node is running"
//	@Router			/status [get]
func statusHandler(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("Received request for /status")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "Control node is running"}`))
}

// loginHandler godoc
//
//	@Summary		Login to the control node
//	@Description	Login to the control node
//	@Tags			auth
//	@Accept			x-www-form-urlencoded
//	@Produce		plain
//	@Param			username	formData	string	true	"Username"
//	@Param			password	formData	string	true	"Password"
//	@Success		200			{string}	string	"Login successful"
//	@Failure		401			{string}	string	"Invalid credentials"
//	@Router			/login [post]
func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("Received request for /login")
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		log.Info().Str("username", username).Msg("Attempting login")

		var dbUsername, dbPassword string
		err := db.QueryRow("SELECT username, password FROM users WHERE username = $1", username).Scan(&dbUsername, &dbPassword)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password)) != nil {
			log.Warn().Str("username", username).Msg("Invalid credentials")
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		log.Info().Str("username", username).Msg("Login successful")
		http.SetCookie(w, &http.Cookie{
			Name:  "session_token",
			Value: "authenticated",
			Path:  "/",
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	w.Write([]byte(`
        <html>
        <body>
            <form method="post" action="/login">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username"><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
        </body>
        </html>
    `))
}

// dashboardHandler godoc
//
//	@Summary		Get the dashboard
//	@Description	Get the dashboard
//	@Tags			dashboard
//	@Produce		plain
//	@Success		200	{string}	string	"Welcome to the Control Node Dashboard!"
//	@Router			/dashboard [get]
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("Received request for /dashboard")
	data, err := dashboardHTML.ReadFile("resources/templates/dashboard.html")
	if err != nil {
		log.Error().Msg("Dashboard template file does not exist")
		http.Error(w, "Dashboard template file not found", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Msg("Authenticating request...")
		cookie, err := r.Cookie("session_token")
		if err != nil || cookie.Value != "authenticated" {
			log.Warn().Msg("Authentication failed, redirecting to /login")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		log.Info().Msg("Authentication successful")
		next.ServeHTTP(w, r)
	}
}

// joinHandler godoc
//
//	@Summary		Join a server to the control node
//	@Description	Join a server to the control node
//	@Tags			join
//	@Accept			x-www-form-urlencoded
//	@Produce		plain
//	@Param			join_key	formData	string	true	"Join Key"
//	@Param			server_name	formData	string	true	"Server Name"
//	@Param			server_ip	formData	string	true	"Server IP"
//	@Success		200			{string}	string	"Server joined successfully"
//	@Failure		401			{string}	string	"Invalid join key"
//	@Failure		500			{string}	string	"Failed to generate certificate"
//	@Router			/join [post]
func joinHandler(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("Received request for /join")
	if r.Method == http.MethodPost {
		r.ParseForm()
		joinKey := r.FormValue("join_key")
		serverName := r.FormValue("server_name")
		serverIP := r.FormValue("server_ip")
		log.Info().Str("serverName", serverName).Str("serverIP", serverIP).Str("joinKey", joinKey).Msg("Joining server")

		var keyID int
		err := db.QueryRow("SELECT id FROM join_keys WHERE key = $1 AND server_id IS NULL", joinKey).Scan(&keyID)
		if err != nil {
			log.Warn().Str("joinKey", joinKey).Msg("Invalid join key")
			http.Error(w, "Invalid join key", http.StatusUnauthorized)
			return
		}

		// Generate certificate for the server
		cert, err := generateCertificate(serverName)
		if err != nil {
			log.Error().Str("serverName", serverName).Msg("Failed to generate certificate")
			http.Error(w, "Failed to generate certificate", http.StatusInternalServerError)
			return
		}

		// Insert server into the database
		var serverID int
		err = db.QueryRow("INSERT INTO servers (name, ip, pub_certificate) VALUES ($1, $2, $3) RETURNING id", serverName, serverIP, cert).Scan(&serverID)
		if err != nil {
			log.Error().Str("serverName", serverName).Msg("Failed to register server")
			http.Error(w, "Failed to register server", http.StatusInternalServerError)
			return
		}

		// Update join key with the server ID
		_, err = db.Exec("UPDATE join_keys SET server_id = $1 WHERE id = $2", serverID, keyID)
		if err != nil {
			log.Error().Str("serverName", serverName).Msg("Failed to update join key")
			http.Error(w, "Failed to update join key", http.StatusInternalServerError)
			return
		}

		log.Info().Str("serverName", serverName).Msg("Server joined successfully")
		w.Write([]byte("Server joined successfully"))
		return
	}

	w.Write([]byte(`
        <html>
        <body>
            <form method="post" action="/join">
                <label for="join_key">Join Key:</label>
                <input type="text" id="join_key" name="join_key"><br>
                <label for="server_name">Server Name:</label>
                <input type="text" id="server_name" name="server_name"><br>
                <label for="server_ip">Server IP:</label>
                <input type="text" id="server_ip" name="server_ip"><br>
                <input type="submit" value="Join">
            </form>
        </body>
        </html>
    `))
}

// @Summary Generate Auth Key
// @Description Generates a join key valid for a specified duration (in hours between 1 and 24). Requires an authenticated session.
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param duration formData int true "Duration in hours (1-24)"
// @Success 200 {object} map[string]interface{} "Auth key generated successfully"
// @Failure 400 {string} string "Invalid duration"
// @Failure 500 {string} string "Failed to generate or insert key"
// @Router /generate_auth_key [post]
func generateAuthKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	durationStr := r.FormValue("duration")
	durationHours, err := strconv.Atoi(durationStr)
	if err != nil || durationHours < 1 || durationHours > 24 {
		http.Error(w, "Invalid duration. Must be between 1 and 24 hours.", http.StatusBadRequest)
		return
	}
	// Generate a random 16-byte auth key
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}
	authKey := fmt.Sprintf("%x", keyBytes)
	// Compute expiration time as current Unix time + duration in seconds
	expiration := time.Now().Unix() + int64(durationHours*3600)
	// Insert the join key with the timeout value
	_, err = db.Exec("INSERT INTO join_keys (key, timeout) VALUES ($1, $2)", authKey, expiration)
	if err != nil {
		http.Error(w, "Failed to insert key into database", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"authKey": "%s", "validHours": %d}`, authKey, durationHours)))
}

// generateCertificate generates a self-signed certificate for the server
func generateCertificate(serverName string) (string, error) {
	log.Info().Str("serverName", serverName).Msg("Generating certificate")
	// Generate a self-signed certificate for the server
	cert, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		log.Error().Str("serverName", serverName).Err(err).Msg("Error generating certificate")
		return "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})

	log.Info().Str("serverName", serverName).Msg("Certificate generated successfully")
	return string(certPEM), nil
}

// NEW: Define NodeJoinRequest model
type NodeJoinRequest struct {
	JoinKey  string `json:"join_key"`
	Hostname string `json:"hostname"`
	CSR      string `json:"csr"`
}

// NEW: Define NodeJoinResponse model
type NodeJoinResponse struct {
	Certificate string `json:"certificate"`
}

// @Summary Node Join
// @Description Accepts a join key, hostname, and a certificate signing request (CSR) in JSON, and returns a signed certificate as JSON. No prior authentication is required.
// @Tags node
// @Accept json
// @Produce json
// @Param body body NodeJoinRequest true "Join request"
// @Success 200 {object} NodeJoinResponse "Signed certificate returned successfully"
// @Failure 400 {string} string "Invalid JSON payload or CSR"
// @Failure 401 {string} string "Invalid or expired join key"
// @Router /node_join [post]
func nodeJoinHandler(w http.ResponseWriter, r *http.Request) {
	// NEW: Clean up expired join keys on each join request
	_, err := db.Exec("DELETE FROM join_keys WHERE timeout < strftime('%s','now')")
	if err != nil {
		log.Error().Err(err).Msg("Join key cleanup failed")
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var req NodeJoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Verify join key not expired or used
	var keyID int
	err = db.QueryRow(
		"SELECT id FROM join_keys WHERE key = $1 AND server_id IS NULL AND timeout > strftime('%s','now')",
		req.JoinKey).Scan(&keyID)
	if err != nil {
		http.Error(w, "Invalid or expired join key", http.StatusUnauthorized)
		return
	}

	// Decode the CSR
	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil {
		http.Error(w, "Invalid CSR PEM", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse CSR", http.StatusBadRequest)
		return
	}

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		http.Error(w, "Failed to generate serial number", http.StatusInternalServerError)
		return
	}

	// Create a certificate template
	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.Hostname,
			Organization: []string{"Astra"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour), // 1 day validity
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	caCert, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		http.Error(w, "Failed to load CA certificate", http.StatusInternalServerError)
		return
	}
	caParsed, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		http.Error(w, "Failed to parse CA certificate", http.StatusInternalServerError)
		return
	}

	// Sign the CSR with our CA
	signedCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		&certTemplate,
		caParsed,
		csr.PublicKey,
		caCert.PrivateKey)
	if err != nil {
		http.Error(w, "Certificate signing error", http.StatusInternalServerError)
		return
	}

	// Encode signed cert as PEM
	signedCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCertBytes})

	// Optional: update join_keys or record server info in DB
	resp := NodeJoinResponse{Certificate: string(signedCertPEM)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
