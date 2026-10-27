// cpagx-v3 is the explicit unified Go entry; legacy cpagx defaults are untouched.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"github.com/TonyP4N/cpagx-go/internal/catalog"
	_ "github.com/jackc/pgx/v5/stdlib"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", os.Getenv("CPAG_V3_CONFIG"), "0600 JSON configuration file")
	backfill := flag.Bool("backfill-legacy", false, "one-shot historical preflight reconstruction during maintenance stop")
	flag.Parse()
	if *path == "" {
		log.Fatal("--config or CPAG_V3_CONFIG required")
	}
	cfg, e := catalog.LoadConfig(*path)
	if e != nil {
		log.Fatal(e)
	}
	db, e := sql.Open("pgx", cfg.DatabaseURL)
	if e != nil {
		log.Fatal(e)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = db.PingContext(ctx); e != nil {
		log.Fatal(e)
	}
	public, e := catalog.New(db, cfg)
	if e != nil {
		log.Fatal(e)
	}
	if *backfill {
		ctx, stop := context.WithTimeout(context.Background(), 10*time.Minute)
		defer stop()
		summary, err := public.BackfillLegacy(ctx)
		if err != nil {
			log.Fatal(err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(summary)
		if summary.HasUnresolved() {
			log.Fatal("legacy backfill retained unresolved historical records; trusted backup remains blocked")
		}
		return
	}
	publicServer := &http.Server{Addr: cfg.PublicAddr, Handler: public, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second}
	internalServer := &http.Server{Addr: cfg.InternalAddr, Handler: public.Internal, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	errors := make(chan error, 2)
	go func() { errors <- internalServer.ListenAndServe() }()
	go func() { errors <- publicServer.ListenAndServe() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case e = <-errors:
		log.Printf("listener exited: %v", e)
	case <-signals:
	}
	stop, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	_ = publicServer.Shutdown(stop)
	_ = internalServer.Shutdown(stop)
}
