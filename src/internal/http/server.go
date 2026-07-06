package http

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/jfigge/keephippo/internal/core"
	"github.com/jfigge/keephippo/internal/logical"
)

// Server adapts a core.Core to the HTTP API.
type Server struct {
	core *core.Core
}

// NewServer returns an HTTP server bound to c.
func NewServer(c *core.Core) *Server {
	return &Server{core: c}
}

// Handler builds the /v1/* request router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Control plane (unauthenticated in Phase 1/2).
	mux.HandleFunc("GET /v1/sys/health", s.handleHealth)
	mux.HandleFunc("GET /v1/sys/seal-status", s.handleSealStatus)
	mux.HandleFunc("PUT /v1/sys/init", s.handleInit)
	mux.HandleFunc("POST /v1/sys/init", s.handleInit)
	mux.HandleFunc("PUT /v1/sys/unseal", s.handleUnseal)
	mux.HandleFunc("POST /v1/sys/unseal", s.handleUnseal)
	mux.HandleFunc("PUT /v1/sys/seal", s.handleSeal)
	mux.HandleFunc("POST /v1/sys/seal", s.handleSeal)
	// Mount management (authenticated).
	mux.HandleFunc("GET /v1/sys/mounts", s.handleMountsList)
	mux.HandleFunc("POST /v1/sys/mounts/{path...}", s.handleMountEnable)
	mux.HandleFunc("PUT /v1/sys/mounts/{path...}", s.handleMountEnable)
	mux.HandleFunc("DELETE /v1/sys/mounts/{path...}", s.handleMountDisable)
	mux.HandleFunc("POST /v1/sys/remount", s.handleRemount)
	mux.HandleFunc("PUT /v1/sys/remount", s.handleRemount)
	// Everything else under /v1/ is a logical request.
	mux.HandleFunc("/", s.handleV1)
	return mux
}

// ---- control plane ----

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

func (s *Server) handleSeal(w http.ResponseWriter, _ *http.Request) {
	if err := s.core.Seal(); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondEmpty(w)
}

func (s *Server) writeSealStatus(w http.ResponseWriter) {
	st, err := s.core.SealStatus()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, st)
}

// ---- mount management ----

func (s *Server) handleMountsList(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	data := map[string]any{}
	for _, m := range s.core.ListMounts() {
		data[m.Path] = map[string]any{"type": m.Type, "accessor": m.Accessor, "uuid": m.UUID}
	}
	respondLogical(w, http.StatusOK, data)
}

func (s *Server) handleMountEnable(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	var body struct {
		Type string `json:"type"`
	}
	if err := decodeJSON(r, &body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.core.EnableMount(r.PathValue("path"), body.Type); err != nil {
		writeCoreError(w, err)
		return
	}
	respondEmpty(w)
}

func (s *Server) handleMountDisable(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	if err := s.core.DisableMount(r.PathValue("path")); err != nil {
		writeCoreError(w, err)
		return
	}
	respondEmpty(w)
}

func (s *Server) handleRemount(w http.ResponseWriter, r *http.Request) {
	if !s.authenticate(w, r) {
		return
	}
	var body struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := decodeJSON(r, &body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.core.Remount(body.From, body.To); err != nil {
		writeCoreError(w, err)
		return
	}
	respondEmpty(w)
}

// ---- logical dispatch ----

func (s *Server) handleV1(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		respondError(w, http.StatusNotFound, "unsupported path")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")

	// Unsupported sys/* endpoints (the supported ones are registered explicitly).
	if path == "sys" || strings.HasPrefix(path, "sys/") {
		if s.core.Sealed() {
			respondError(w, http.StatusServiceUnavailable, "keephippo is sealed")
			return
		}
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
		Path:        path,
		ClientToken: r.Header.Get("X-Vault-Token"),
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
	switch op {
	case logical.ReadOperation:
		if resp == nil {
			respondError(w, http.StatusNotFound)
			return
		}
		respondLogical(w, http.StatusOK, resp.Data)
	case logical.ListOperation:
		if resp == nil {
			respondError(w, http.StatusNotFound)
			return
		}
		if keys, _ := resp.Data["keys"].([]string); len(keys) == 0 {
			respondError(w, http.StatusNotFound)
			return
		}
		respondLogical(w, http.StatusOK, resp.Data)
	default: // create/update/delete
		respondEmpty(w)
	}
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if _, err := s.core.Authenticate(r.Header.Get("X-Vault-Token")); err != nil {
		writeCoreError(w, err)
		return false
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

func writeCoreError(w http.ResponseWriter, err error) {
	var ce *core.CodedError
	if errors.As(err, &ce) {
		respondError(w, ce.Status, ce.Message)
		return
	}
	respondError(w, http.StatusInternalServerError, err.Error())
}
