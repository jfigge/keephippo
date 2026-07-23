package http

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/core"
	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/web"
)

// Server adapts a core.Core to the HTTP API.
type Server struct {
	core      *core.Core
	uiEnabled bool
}

// Option configures a Server.
type Option func(*Server)

// WithUI enables serving the embedded web console at /ui.
func WithUI(enabled bool) Option {
	return func(s *Server) { s.uiEnabled = enabled }
}

// NewServer returns an HTTP server bound to c.
func NewServer(c *core.Core, opts ...Option) *Server {
	s := &Server{core: c}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Handler builds the /v1/* request router. Only the pre-unseal control plane
// (health, seal-status, init, unseal) is handled directly; everything else —
// sys/*, auth/*, and logical secret paths — is routed through the core, which
// authenticates and authorizes every request.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sys/health", s.handleHealth)
	mux.HandleFunc("GET /v1/sys/seal-status", s.handleSealStatus)
	mux.HandleFunc("PUT /v1/sys/init", s.handleInit)
	mux.HandleFunc("POST /v1/sys/init", s.handleInit)
	mux.HandleFunc("PUT /v1/sys/unseal", s.handleUnseal)
	mux.HandleFunc("POST /v1/sys/unseal", s.handleUnseal)
	if s.uiEnabled {
		fileServer := http.StripPrefix("/ui", http.FileServer(http.FS(web.Assets)))
		mux.Handle("GET /ui/", fileServer)
		mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/", http.StatusFound)
		})
		swaggerServer := http.StripPrefix("/swagger", http.FileServer(http.FS(web.Swagger())))
		mux.Handle("GET /swagger/", swaggerServer)
		mux.HandleFunc("GET /swagger", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/swagger/", http.StatusFound)
		})
		mux.HandleFunc("GET /favicon.ico", s.handleFavicon)
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/", http.StatusFound)
		})
	}
	mux.HandleFunc("/", s.handleV1)
	return mux
}

// handleFavicon serves the browser-tab icon from the embedded icon set.
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	b, err := web.Assets.ReadFile("icons/32x32.png")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(b)
}

// ---- pre-unseal control plane (unauthenticated) ----

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	h, err := s.core.Health()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	status := http.StatusOK
	switch {
	case !h.Initialized:
		status = http.StatusNotImplemented // 501: not initialized (matches Vault)
	case h.Sealed:
		status = http.StatusServiceUnavailable // 503: sealed
	}
	respondJSON(w, status, h)
}

func (s *Server) handleSealStatus(w http.ResponseWriter, _ *http.Request) {
	s.writeSealStatus(w)
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SecretShares    int `json:"secret_shares"`
		SecretThreshold int `json:"secret_threshold"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if initialized, err := s.core.Initialized(); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	} else if initialized {
		respondError(w, http.StatusBadRequest, "keephippo is already initialized")
		return
	}

	res, err := s.core.Initialize(core.InitParams{
		SecretShares:    req.SecretShares,
		SecretThreshold: req.SecretThreshold,
	})
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	keysHex := make([]string, len(res.Keys))
	keysB64 := make([]string, len(res.Keys))
	for i, k := range res.Keys {
		keysHex[i] = hex.EncodeToString(k)
		keysB64[i] = base64.StdEncoding.EncodeToString(k)
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"keys":        keysHex,
		"keys_base64": keysB64,
		"root_token":  res.RootToken,
	})
}

func (s *Server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key   string `json:"key"`
		Reset bool   `json:"reset"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Reset {
		s.core.ResetUnseal()
		s.writeSealStatus(w)
		return
	}
	raw, err := decodeUnsealKey(req.Key)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.core.Unseal(raw); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeSealStatus(w)
}

func (s *Server) writeSealStatus(w http.ResponseWriter) {
	st, err := s.core.SealStatus()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, st)
}

// ---- authenticated dispatch ----

func (s *Server) handleV1(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		respondError(w, http.StatusNotFound, "unsupported path")
		return
	}
	op, ok := operationForMethod(r)
	if !ok {
		respondError(w, http.StatusMethodNotAllowed, "unsupported method")
		return
	}

	req := &logical.Request{
		Operation:   op,
		Path:        strings.TrimPrefix(r.URL.Path, "/v1/"),
		ClientToken: r.Header.Get("X-Vault-Token"),
		Query:       r.URL.Query(),
		RemoteAddr:  r.RemoteAddr,
		WrapTTL:     parseWrapTTL(r.Header.Get("X-Vault-Wrap-TTL")),
	}
	if r.TLS != nil {
		req.PeerCertificates = r.TLS.PeerCertificates
	}
	if op == logical.CreateOperation || op == logical.UpdateOperation {
		data := map[string]any{}
		if err := decodeJSON(r, &data); err != nil {
			respondError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.Data = data
	}

	resp, err := s.core.HandleRequest(req)
	if err != nil {
		writeCoreError(w, err)
		return
	}
	renderLogical(w, op, resp)
}

func renderLogical(w http.ResponseWriter, op logical.Operation, resp *logical.Response) {
	switch {
	case resp != nil && resp.WrapInfo != nil:
		respondJSON(w, http.StatusOK, &Response{RequestID: requestID(), WrapInfo: resp.WrapInfo})
	case resp != nil && resp.Auth != nil:
		respondJSON(w, http.StatusOK, &Response{RequestID: requestID(), Data: resp.Data, Auth: resp.Auth})
	case op == logical.ListOperation:
		if resp == nil || keysEmpty(resp.Data) {
			respondError(w, http.StatusNotFound)
			return
		}
		respondLogical(w, http.StatusOK, resp.Data)
	case op == logical.ReadOperation:
		if resp == nil {
			respondError(w, http.StatusNotFound)
			return
		}
		respondLogical(w, http.StatusOK, resp.Data)
	default: // create/update/delete
		if resp == nil || resp.Data == nil {
			respondEmpty(w)
			return
		}
		respondLogical(w, http.StatusOK, resp.Data)
	}
}

func keysEmpty(data map[string]any) bool {
	switch k := data["keys"].(type) {
	case []string:
		return len(k) == 0
	case []any:
		return len(k) == 0
	}
	return true
}

func operationForMethod(r *http.Request) (logical.Operation, bool) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("list") == "true" {
			return logical.ListOperation, true
		}
		return logical.ReadOperation, true
	case "LIST":
		return logical.ListOperation, true
	case http.MethodPost, http.MethodPut:
		return logical.UpdateOperation, true
	case http.MethodDelete:
		return logical.DeleteOperation, true
	default:
		return "", false
	}
}

// parseWrapTTL parses the X-Vault-Wrap-TTL header (a Go duration like "60s" or a
// bare number of seconds). Returns 0 when absent or unparseable.
func parseWrapTTL(s string) time.Duration {
	if s == "" {
		return 0
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second
	}
	return 0
}

func writeCoreError(w http.ResponseWriter, err error) {
	var ce *core.CodedError
	if errors.As(err, &ce) {
		respondError(w, ce.Status, ce.Message)
		return
	}
	var le *logical.CodedError
	if errors.As(err, &le) {
		respondError(w, le.Status, le.Message)
		return
	}
	respondError(w, http.StatusInternalServerError, err.Error())
}
