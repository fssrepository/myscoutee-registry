package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/httpapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		err = runHealthcheck()
	} else if len(os.Args) == 2 && os.Args[1] == "initialize" {
		err = runInitialize(logger)
	} else if len(os.Args) != 1 {
		err = fmt.Errorf("usage: %s [healthcheck|initialize]", os.Args[0])
	} else {
		err = runServer(logger)
	}
	if err != nil {
		logger.Error("registry stopped", "error", err)
		os.Exit(1)
	}
}

func runInitialize(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keyID, err := app.InitializeProvisioned(ctx, cfg, app.Options{Logger: logger})
	if err != nil {
		return fmt.Errorf("initialize provisioned registry identity: %w", err)
	}
	logger.Info(
		"provisioned registry identity is initialized",
		"registry_scope", cfg.RegistryScope,
		"registry_key_id", keyID,
	)
	return nil
}

func runServer(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	rootContext, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	runtime, err := app.Bootstrap(rootContext, cfg, app.Options{Logger: logger})
	if err != nil {
		return fmt.Errorf("bootstrap registry: %w", err)
	}
	defer runtime.Close()

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddress, err)
	}
	defer listener.Close()

	handler := httpapi.New(runtime.Service, httpapi.Options{
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
		Logger:              logger,
	})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	workerContext, cancelWorker := context.WithCancel(rootContext)
	defer cancelWorker()
	go runtime.Service.RunCheckpointWorker(workerContext, cfg.CheckpointInterval)

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()
	logger.Info(
		"registry is accepting requests",
		"address", listener.Addr().String(),
		"registry_key_id", runtime.SigningKey.KeyID(),
	)

	select {
	case serveErr := <-serverErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve registry HTTP: %w", serveErr)
	case <-rootContext.Done():
	}

	cancelWorker()
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shut down registry HTTP server: %w", err)
	}
	serveErr := <-serverErrors
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("serve registry HTTP: %w", serveErr)
	}
	logger.Info("registry shut down cleanly")
	return nil
}

func runHealthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	request, err := http.NewRequest(http.MethodGet, cfg.HealthcheckURL, nil)
	if err != nil {
		return fmt.Errorf("build health-check request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("call registry health endpoint: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("registry health endpoint returned %s", response.Status)
	}
	return nil
}
