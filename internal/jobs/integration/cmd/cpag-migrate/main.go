// cpag-migrate serializes and records the exact migration bytes transactionally.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

func main() {
	if err := migrate(); err != nil {
		log.Fatal(err)
	}
}
func migrate() error {
	raw, err := os.ReadFile("/etc/cpag/app.json")
	if err != nil {
		return err
	}
	var cfg struct {
		URL string `json:"database_url"`
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	db, err := sql.Open("pgx", cfg.URL)
	if err != nil {
		return fmt.Errorf("open migration database: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(1729360253)"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(1729360253)")
	if _, err = conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS cpag_schema_migrations(name text PRIMARY KEY,sha256 text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	files, err := filepath.Glob("/opt/cpag/migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	pattern := regexp.MustCompile(`^[0-9]{3}_[a-z0-9_]+\.sql$`)
	count := 0
	for _, file := range files {
		name := filepath.Base(file)
		if !pattern.MatchString(name) {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		want := hex.EncodeToString(digest[:])
		var have string
		err = conn.QueryRowContext(ctx, "SELECT sha256 FROM cpag_schema_migrations WHERE name=$1", name).Scan(&have)
		if err == nil {
			if have != want {
				return fmt.Errorf("migration checksum changed: %s", name)
			}
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO cpag_schema_migrations(name,sha256) VALUES($1,$2)", name, want); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		count++
	}
	if len(files) == 0 {
		return fmt.Errorf("migration files absent")
	}
	log.Printf("CPAG v3 migrations ready; %d newly applied", count)
	return nil
}
