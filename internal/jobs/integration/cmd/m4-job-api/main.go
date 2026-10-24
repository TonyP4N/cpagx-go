// Explicitly launched M4 service; the ordinary application never imports this runner.
package main

import (
	"context"
	"database/sql"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	if os.Getenv("CPAG_ENABLE_M4") != "1" {
		log.Fatal("CPAG_ENABLE_M4=1 required")
	}
	dsn := os.Getenv("M4_DATABASE_URL")
	if dsn == "" {
		log.Fatal("M4_DATABASE_URL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		log.Fatal(err)
	}
	h, err := jobapi.New(jobs.Repository{DB: db}, os.Getenv("CPAG_SHARED_ROOT"), os.Getenv("CPAG_WORKER_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("CPAG_JOB_API_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8094"
	}
	server := http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	log.Fatal(server.ListenAndServe())
}
