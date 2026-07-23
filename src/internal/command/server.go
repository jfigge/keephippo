package command

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/internal/core"
	kphttp "github.com/jfigge/keephippo/internal/http"
	"github.com/jfigge/keephippo/internal/physical"
	"github.com/jfigge/keephippo/internal/physical/file"
	"github.com/jfigge/keephippo/internal/physical/inmem"
	"github.com/jfigge/keephippo/internal/seal"
)

const defaultListenAddr = "127.0.0.1:8200"

func newServerCmd() *cobra.Command {
	var dev bool
	var configPath string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start a keephippo server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dev {
				return runDevServer(cmd)
			}
			if configPath == "" {
				return errors.New("a --config file is required (or use --dev)")
			}
			return runServer(cmd, configPath)
		},
	}
	cmd.Flags().BoolVar(&dev, "dev", false, "Start an in-memory dev server (auto-unsealed; not for production)")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to an HCL or JSON config file")
	return cmd
}

// runDevServer starts an in-memory, auto-unsealed server and prints the single
// unseal key and root token — like `vault server -dev`.
func runDevServer(cmd *cobra.Command) error {
	c := core.New(inmem.New(), "inmem")
	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		return err
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "==> keephippo server (dev mode) — in-memory, auto-unsealed, TLS disabled")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Unseal Key: %s\n", hex.EncodeToString(res.Keys[0]))
	fmt.Fprintf(w, "Root Token: %s\n", res.RootToken)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "export KEEPHIPPO_ADDR=http://%s\n", defaultListenAddr)
	fmt.Fprintf(w, "export KEEPHIPPO_TOKEN=%s\n", res.RootToken)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Web console:  http://%s/ui\n", defaultListenAddr)
	fmt.Fprintf(w, "Swagger docs: http://%s/swagger\n", defaultListenAddr)
	fmt.Fprintf(w, "Listening on: http://%s\n", defaultListenAddr)
	return serve(cmd, defaultListenAddr, c, true)
}

// runServer starts a configured, sealed server that must be initialized and
// unsealed by an operator.
func runServer(cmd *cobra.Command, configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	backend, storageType, err := buildBackend(cfg.Storage)
	if err != nil {
		return err
	}
	if closer, ok := backend.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}

	addr := defaultListenAddr
	if cfg.Listener != nil && cfg.Listener.Address != "" {
		addr = cfg.Listener.Address
	}

	c := core.New(backend, storageType)
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "==> keephippo server started (storage: %s, listener: %s)\n", storageType, addr)

	if cfg.Seal != nil && cfg.Seal.Type == "transit" {
		autoSeal, err := seal.NewTransitSeal(seal.TransitSealConfig{
			Address:       cfg.Seal.Address,
			Token:         cfg.Seal.Token,
			MountPath:     cfg.Seal.MountPath,
			KeyName:       cfg.Seal.KeyName,
			TLSSkipVerify: cfg.Seal.TLSSkipVerify,
		})
		if err != nil {
			return fmt.Errorf("configure transit auto-seal: %w", err)
		}
		c.SetAutoSeal(autoSeal)
		if unsealed, err := c.AutoUnseal(); err != nil {
			fmt.Fprintf(w, "auto-unseal failed (%v); the server remains sealed.\n", err)
		} else if unsealed {
			fmt.Fprintln(w, "The server auto-unsealed via the transit seal.")
		} else {
			fmt.Fprintln(w, "Auto-seal configured. Run 'keephippo operator init' to initialize.")
		}
	} else {
		fmt.Fprintln(w, "The server is sealed. Run 'keephippo operator init', then 'keephippo operator unseal'.")
	}
	if cfg.UI {
		fmt.Fprintf(w, "Web console enabled at %s/ui\n", addr)
	}
	return serve(cmd, addr, c, cfg.UI)
}

func buildBackend(s *storageStanza) (physical.Backend, string, error) {
	switch s.Type {
	case "inmem":
		return inmem.New(), "inmem", nil
	case "file":
		if s.Path == "" {
			return nil, "", errors.New(`storage "file": path is required`)
		}
		b, err := file.New(filepath.Join(s.Path, "keephippo.db"))
		if err != nil {
			return nil, "", err
		}
		return b, "file", nil
	default:
		return nil, "", fmt.Errorf("unsupported storage type %q (want \"file\" or \"inmem\")", s.Type)
	}
}

// serve runs the HTTP server until an interrupt/terminate signal, then shuts
// down gracefully.
func serve(cmd *cobra.Command, addr string, c *core.Core, ui bool) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           kphttp.NewServer(c, kphttp.WithUI(ui)).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-sigCh:
		fmt.Fprintln(cmd.OutOrStdout(), "\n==> shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
