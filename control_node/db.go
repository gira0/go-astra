package main

import (
	"database/sql"
	"os"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

var (
	db    *sql.DB
	debug = true
)

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
		timeout INTEGER,
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
