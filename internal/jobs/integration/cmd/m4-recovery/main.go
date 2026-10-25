// Opt-in recovery daemon: the only non-API component allowed database access.
package main

import (
	"context"
	"database/sql"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if os.Getenv("CPAG_ENABLE_M4") != "1" {
		log.Fatal("CPAG_ENABLE_M4=1 required")
	}
	root := os.Getenv("CPAG_SHARED_ROOT")
	dsn := os.Getenv("M4_DATABASE_URL")
	if root == "" || dsn == "" {
		log.Fatal("CPAG_SHARED_ROOT and M4_DATABASE_URL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobs.Repository{DB: db}.RunRecovery(ctx, root, time.Second, func(err error) { log.Printf("recovery pass failed: %v", err) })
}
