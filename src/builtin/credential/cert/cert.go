// Package cert implements the cert (TLS client-certificate) auth method: a
// client authenticates by presenting a TLS certificate that matches a trusted
// certificate or is issued by a trusted CA, and receives a policy-scoped token.
package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
)

// Backend is the cert auth method over a per-mount storage view.
type Backend struct {
	storage logical.Storage
}

var (
	_ logical.Backend         = (*Backend)(nil)
	_ logical.Unauthenticated = (*Backend)(nil)
)

// New returns a cert backend backed by storage.
func New(storage logical.Storage) *Backend { return &Backend{storage: storage} }

// certEntry is a stored trusted certificate (a leaf or a CA) and its grant.
type certEntry struct {
	Name        string   `json:"name"`
	Certificate string   `json:"certificate"` // PEM
	Policies    []string `json:"policies"`
	DisplayName string   `json:"display_name"`
	TokenTTL    int64    `json:"token_ttl"`
}

func coded(status int, msg string) error { return &logical.CodedError{Status: status, Message: msg} }

// IsUnauthenticated reports whether path is the login path.
func (b *Backend) IsUnauthenticated(_ logical.Operation, path string) bool { return path == "login" }

func (b *Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	path := req.Path
	switch {
	case path == "login":
		return b.login(req)
	case path == "certs":
		if req.Operation == logical.ListOperation {
			keys, err := b.storage.List("cert/")
			if err != nil {
				return nil, err
			}
			return logical.ListResponse(keys), nil
		}
		return nil, coded(404, "unsupported path")
	case strings.HasPrefix(path, "certs/"):
		return b.certOp(req, strings.TrimPrefix(path, "certs/"))
	default:
		return nil, coded(404, fmt.Sprintf("unsupported path %q", path))
	}
}

func (b *Backend) certOp(req *logical.Request, name string) (*logical.Response, error) {
	if name == "" {
		return nil, coded(400, "missing certificate name")
	}
	switch req.Operation {
	case logical.CreateOperation, logical.UpdateOperation:
		pemStr := logical.FieldString(req.Data, "certificate")
		if pemStr == "" {
			return nil, coded(400, "certificate (PEM) is required")
		}
		if _, err := parseCert(pemStr); err != nil {
			return nil, coded(400, "certificate is not valid PEM/x509")
		}
		ce := &certEntry{
			Name:        name,
			Certificate: pemStr,
			Policies:    logical.FieldStringSlice(req.Data, "policies"),
			DisplayName: logical.FieldString(req.Data, "display_name"),
			TokenTTL:    int64(logical.FieldDuration(req.Data, "token_ttl") / time.Second),
		}
		return nil, b.save(name, ce)
	case logical.ReadOperation:
		ce, err := b.load(name)
		if err != nil || ce == nil {
			return nil, err
		}
		return &logical.Response{Data: map[string]any{
			"certificate": ce.Certificate, "policies": ce.Policies,
			"display_name": ce.DisplayName, "token_ttl": ce.TokenTTL,
		}}, nil
	case logical.DeleteOperation:
		return nil, b.storage.Delete(certStorageKey(name))
	default:
		return nil, coded(405, "unsupported operation")
	}
}

func (b *Backend) login(req *logical.Request) (*logical.Response, error) {
	if len(req.PeerCertificates) == 0 {
		return nil, coded(400, "no client certificate was presented")
	}
	peer := req.PeerCertificates[0]

	names, err := b.storage.List("cert/")
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if strings.HasSuffix(name, "/") {
			continue
		}
		ce, err := b.load(name)
		if err != nil || ce == nil {
			continue
		}
		trusted, err := parseCert(ce.Certificate)
		if err != nil {
			continue
		}
		if certMatches(peer, trusted) {
			display := ce.DisplayName
			if display == "" {
				display = "cert-" + name
			}
			return &logical.Response{Auth: &logical.Auth{
				Policies:      ce.Policies,
				LeaseDuration: ce.TokenTTL,
				Renewable:     true,
				DisplayName:   display,
				Alias:         name,
				Metadata:      map[string]string{"cert_name": name, "common_name": peer.Subject.CommonName},
			}}, nil
		}
	}
	return nil, coded(400, "no trusted certificate matched the presented client certificate")
}

// certMatches reports whether peer is the trusted certificate itself or was
// issued by it (treating the trusted cert as a CA).
func certMatches(peer, trusted *x509.Certificate) bool {
	if bytes.Equal(peer.Raw, trusted.Raw) {
		return true
	}
	pool := x509.NewCertPool()
	pool.AddCert(trusted)
	_, err := peer.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

func parseCert(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (b *Backend) load(name string) (*certEntry, error) {
	e, err := b.storage.Get(certStorageKey(name))
	if err != nil || e == nil {
		return nil, err
	}
	var ce certEntry
	if err := json.Unmarshal(e.Value, &ce); err != nil {
		return nil, err
	}
	return &ce, nil
}

func (b *Backend) save(name string, ce *certEntry) error {
	blob, err := json.Marshal(ce)
	if err != nil {
		return err
	}
	return b.storage.Put(&logical.StorageEntry{Key: certStorageKey(name), Value: blob})
}

func certStorageKey(name string) string { return "cert/" + name }
