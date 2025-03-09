package main

import (
	"embed"
	"net/http"
	"os"
	"time"

	_ "control_node/docs"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"
)

//go:embed resources/templates/* resources/js/* resources/css/*
var embeddedFiles embed.FS

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

func startControlNode() {
	log.Info().Msg("Starting control node...")

	// Start HTTP API
	go func() {
		log.Info().Msg("Starting control node API...")

		http.HandleFunc("/status", statusHandler)
		http.HandleFunc("/login", loginHandler)
		http.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
		http.HandleFunc("/join", joinHandler)
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(embeddedFiles))))

		// Swagger UI
		http.HandleFunc("/swagger/", httpSwagger.WrapHandler)

		log.Info().Msg("Control node API is listening on localhost:8081")
		log.Fatal().Err(http.ListenAndServe(":8081", nil)).Msg("Failed to start HTTP server")
	}()

	log.Info().Msg("Control node started")

	// Schedule data transfers
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		log.Info().Msg("Scheduled data transfer")
		// Trigger data transfer
		// ...existing code...
	}
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
