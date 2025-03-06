package main

import (
	_ "control_node/docs"
	"crypto/tls"
	"database/sql"
	"encoding/pem"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"
)

var (
	db    *sql.DB
	debug = true
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if debug {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).With().Caller().Logger()
	}
}

// @title			Astra Control Node API
// @version		1.0
// @description	This is the API documentation for the Astra Control Node.
// @host			localhost:8081
// @BasePath		/
func main() {
	log.Info().Msg("Starting Astra Control Node...")

	var err error
	db, err = initDB()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer db.Close()
	log.Info().Msg("Database initialized successfully")

	// Initialize database schema
	err = initSchema()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database schema")
	}
	log.Info().Msg("Database schema initialized successfully")

	startControlNode()
}

func initDB() (*sql.DB, error) {
	dbType := os.Getenv("DB_TYPE")
	log.Info().Str("dbType", dbType).Msg("Database type")
	if dbType == "postgres" {
		connStr := "user=youruser dbname=yourdb sslmode=disable"
		log.Info().Str("connStr", connStr).Msg("Connecting to PostgreSQL")
		return sql.Open("postgres", connStr)
	}
	log.Info().Msg("Connecting to SQLite3 with default database file: ./control_node.db")
	return sql.Open("sqlite3", "./control_node.db")
}

func initSchema() error {
	log.Info().Msg("Initializing database schema...")
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		permissions TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS user_roles (
		user_id INTEGER NOT NULL,
		role_id INTEGER NOT NULL,
		PRIMARY KEY (user_id, role_id),
		FOREIGN KEY (user_id) REFERENCES users(id),
		FOREIGN KEY (role_id) REFERENCES roles(id)
	);

	CREATE TABLE IF NOT EXISTS servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		ip TEXT NOT NULL,
		pub_certificate TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS transfers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_server_id INTEGER NOT NULL,
		dest_server_id INTEGER NOT NULL,
		source_path TEXT NOT NULL,
		dest_path TEXT NOT NULL,
		status TEXT NOT NULL,
		FOREIGN KEY (source_server_id) REFERENCES servers(id),
		FOREIGN KEY (dest_server_id) REFERENCES servers(id)
	);

	CREATE TABLE IF NOT EXISTS transfer_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		transfer_id INTEGER NOT NULL,
		file_path TEXT NOT NULL,
		status TEXT NOT NULL,
		progress INTEGER NOT NULL,
		FOREIGN KEY (transfer_id) REFERENCES transfers(id)
	);

	CREATE TABLE IF NOT EXISTS join_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT NOT NULL,
		server_id INTEGER,
		FOREIGN KEY (server_id) REFERENCES servers(id)
	);
	`
	_, err := db.Exec(schema)
	if err != nil {
		log.Error().Err(err).Msg("Error executing schema")
		return err
	}

	log.Info().Msg("Inserting initial roles and users...")
	// Insert admin role
	_, err = db.Exec(`
		INSERT INTO roles (name, permissions) 
		SELECT 'admin', 'manage_users,manage_transfers,view_transfers' 
		WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name='admin');
	`)
	if err != nil {
		log.Error().Err(err).Msg("Error inserting initial roles")
		return err
	}

	// Insert admin user with hashed password
	adminPassword := "password"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Error hashing admin password")
		return err
	}
	_, err = db.Exec(`
		INSERT INTO users (username, password) 
		SELECT 'admin', $1 
		WHERE NOT EXISTS (SELECT 1 FROM users WHERE username='admin');
	`, string(hashedPassword))
	if err != nil {
		log.Error().Err(err).Msg("Error inserting admin user")
		return err
	}

	// Retrieve user_id and role_id for admin
	var userID, roleID int
	err = db.QueryRow("SELECT id FROM users WHERE username = 'admin'").Scan(&userID)
	if err != nil {
		log.Error().Err(err).Msg("Error retrieving user_id for admin")
		return err
	}
	err = db.QueryRow("SELECT id FROM roles WHERE name = 'admin'").Scan(&roleID)
	if err != nil {
		log.Error().Err(err).Msg("Error retrieving role_id for admin")
		return err
	}

	// Insert admin user role
	_, err = db.Exec(`
		INSERT INTO user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING;
	`, userID, roleID)
	if err != nil {
		log.Error().Err(err).Msg("Error inserting admin user role")
		return err
	}

	log.Info().Msg("Initial roles and users inserted successfully")
	return nil
}

func startControlNode() {
	log.Info().Msg("Starting control node...")

	// Start HTTP API
	go startControlNodeAPI()

	log.Info().Msg("Control node started")

	// Schedule data transfers
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Info().Msg("Scheduled data transfer")
			// Trigger data transfer
			// ...existing code...
		}
	}
}

func startControlNodeAPI() {
	log.Info().Msg("Starting control node API...")

	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
	http.HandleFunc("/join", joinHandler)

	// Swagger UI
	http.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	log.Info().Msg("Control node API is listening on localhost:8081")
	log.Fatal().Err(http.ListenAndServe(":8081", nil)).Msg("Failed to start HTTP server")
}

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
//	@Success		200	{string}	string	"Welcome to the dashboard!"
//	@Router			/dashboard [get]
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("Received request for /dashboard")
	w.Write([]byte("Welcome to the dashboard!"))
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

const serverCert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJALa6g4Gz5vZOMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEQMA4GA1UEBwwHQmVya2VsZXkxEDAOBgNVBAoM
B0V4YW1wbGUwHhcNMTgwNTE1MTYxNzI2WhcNMjgwNTEyMTYxNzI2WjBFMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCQ0ExEDAOBgNVBAcMB0JlcmtlbGV5MRAwDgYDVQQK
DAdFeGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QK7z5Z5
...
-----END CERTIFICATE-----`

const serverKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDtArvPlnk...
...
-----END PRIVATE KEY-----`
