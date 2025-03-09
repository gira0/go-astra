package main

import (
	"crypto/tls"
	"embed"
	"encoding/pem"
	"net/http"

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
	w.Write([]byte("Control node is running"))
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
