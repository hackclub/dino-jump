package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

type DatabaseConfig struct {
	DB     *sql.DB
	Driver string
}

// NewDatabaseConnection creates a database connection based on DATABASE_URL or defaults to SQLite
func NewDatabaseConnection() (*DatabaseConfig, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	var db *sql.DB
	var err error
	var dbDriver string

	if databaseURL != "" {
		// Parse database URL to determine driver
		if strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://") {
			dbDriver = "postgres"
			db, err = sql.Open("postgres", databaseURL)
		} else if strings.HasPrefix(databaseURL, "sqlite3://") || strings.HasPrefix(databaseURL, "file:") {
			dbDriver = "sqlite3"
			// Remove sqlite3:// prefix if present
			dbPath := strings.TrimPrefix(databaseURL, "sqlite3://")
			dbPath = strings.TrimPrefix(dbPath, "file:")
			db, err = sql.Open("sqlite3", dbPath)
		} else {
			return nil, fmt.Errorf("unsupported DATABASE_URL format: %s (must start with postgres://, postgresql://, sqlite3://, or file:)", databaseURL)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %v", err)
		}
		log.Printf("Connected to %s database from DATABASE_URL", dbDriver)
	} else {
		// Default to SQLite
		dbDriver = "sqlite3"
		db, err = sql.Open("sqlite3", "./tokens.db")
		if err != nil {
			return nil, err
		}
		log.Println("Using default SQLite database: ./tokens.db")
	}

	return &DatabaseConfig{
		DB:     db,
		Driver: dbDriver,
	}, nil
}

// RunMigrations runs database migrations for the configured database
func (config *DatabaseConfig) RunMigrations() error {
	var driver database.Driver
	var err error

	switch config.Driver {
	case "postgres":
		driver, err = postgres.WithInstance(config.DB, &postgres.Config{})
	case "sqlite3":
		driver, err = sqlite3.WithInstance(config.DB, &sqlite3.Config{})
	default:
		return fmt.Errorf("unsupported database driver: %s", config.Driver)
	}

	if err != nil {
		return fmt.Errorf("failed to create migration driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://migrations", config.Driver, driver)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %v", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %v", err)
	}

	log.Println("Migrations completed successfully")
	return nil
}
