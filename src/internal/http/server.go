package http

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/jfigge/keephippo/internal/core"
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
	mux.HandleFunc("GET /v1/sys/health", s.handleHealth)
	mux.HandleFunc("GET /v1/sys/seal-status", s.handleSealStatus)
	mux.HandleFunc("PUT /v1/sys/init", s.handleInit)
	mux.HandleFunc("POST /v1/sys/init", s.handleInit)
	mux.HandleFunc("PUT /v1/sys/unseal", s.handleUnseal)
	mux.HandleFunc("POST /v1/sys/unseal", s.handleUnseal)
	mux.HandleFunc("PUT /v1/sys/seal", s.handleSeal)
	mux.HandleFunc("POST /v1/sys/seal", s.handleSeal)
	mux.HandleFunc("/", s.handleCatchAll)
	return mux
}

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

// handleCatchAll answers any unmapped path. While sealed it reports 503 for
// /v1/* requests (the server serves almost nothing until unsealed); otherwise
// it reports 404 for an unsupported path.
func (s *Server) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/") && s.core.Sealed() {
		respondError(w, http.StatusServiceUnavailable, "keephippo is sealed")
		return
	}
	respondError(w, http.StatusNotFound, "unsupported path")
}

func (s *Server) writeSealStatus(w http.ResponseWriter) {
	st, err := s.core.SealStatus()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, st)
}
