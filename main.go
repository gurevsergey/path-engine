// path-engine computes historical network paths from Prometheus and correlates
// the exporter hops with NetFlow. It never changes the monitored network.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func envInt(name string, fallback int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return n, nil
}
func run() error {
	cfg, err := loadConfig(or(os.Getenv("CONFIG_PATH"), "/config.yml"), or(os.Getenv("NETMAP_PATH"), "/netmap-config.json"))
	if err != nil {
		return err
	}
	port, err := envInt("LISTEN_PORT", 49105)
	if err != nil || port > 65535 {
		return fmt.Errorf("invalid LISTEN_PORT")
	}
	interval, err := envInt("REFRESH_INTERVAL", 120)
	if err != nil {
		return err
	}
	watch, err := envInt("WATCH_WINDOW", 900)
	if err != nil {
		return err
	}
	s := &State{cfg: cfg, prom: &Prom{URL: or(os.Getenv("PROMETHEUS_URL"), "http://prometheus:9090")}, nf: newNetFlow(), cache: map[int64]*Snapshot{}, findings: []Finding{}, pairs: []PairResult{}, watchWindow: float64(watch)}
	if s.nf.enabled() {
		log.Printf("NetFlow: включён, %s", s.nf.URL)
	} else {
		log.Print("NetFlow: выключен (не заданы NETFLOW_OS_*)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go s.loop(ctx, time.Duration(interval)*time.Second)
	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-done:
		}
	}()
	log.Printf("path-engine listening on %s", server.Addr)
	err = server.ListenAndServe()
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
