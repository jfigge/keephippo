//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfigge/keephippo/api"
	"github.com/jfigge/keephippo/internal/core"
	kphttp "github.com/jfigge/keephippo/internal/http"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

// newTLSServer starts an unsealed in-memory server over TLS that requests (but
// does not require) client certificates.
func newTLSServer(t *testing.T) (string, string) {
	t.Helper()
	c := core.New(inmem.New(), "inmem")
	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	srv := httptest.NewUnstartedServer(kphttp.NewServer(c).Handler())
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert} //nolint:gosec // client cert requested, verified in-app
	srv.StartTLS()
	t.Cleanup(srv.Close)
	t.Cleanup(func() { _ = c.Seal() })
	return srv.URL, res.RootToken
}

// makeClientCert returns a self-signed client certificate (PEM) and a
// tls.Certificate for presenting it.
func makeClientCert(t *testing.T, cn string) (string, tls.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(certPEM), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestCertAuthLogin is the Phase 8 cert-auth path: register a trusted client
// certificate, present it over TLS, and receive a policy-scoped token.
func TestCertAuthLogin(t *testing.T) {
	url, root := newTLSServer(t)
	rc, err := api.NewClient(api.Config{Address: url, Token: root, TLSSkipVerify: true})
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}

	if err := rc.AuthEnable("cert", "cert"); err != nil {
		t.Fatalf("enable cert: %v", err)
	}
	certPEM, clientCert := makeClientCert(t, "web-client")
	if err := rc.Write("auth/cert/certs/web", map[string]any{
		"certificate": certPEM, "policies": "webpol",
	}); err != nil {
		t.Fatalf("register cert: %v", err)
	}

	// Login presenting the client certificate over TLS.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, //nolint:gosec // test server uses a self-signed cert
	}}}
	auth := certLogin(t, hc, url)
	if auth.ClientToken == "" {
		t.Fatal("no token from cert login")
	}
	if !sliceContains(auth.Policies, "webpol") {
		t.Fatalf("cert token missing 'webpol': %v", auth.Policies)
	}

	// A login without a client certificate is rejected.
	resp, err := rc.Do(http.MethodPost, "/v1/auth/cert/login", map[string]any{})
	if err == nil {
		t.Fatalf("login without a client cert should fail: %+v", resp)
	}
}

func certLogin(t *testing.T, hc *http.Client, url string) *api.AuthInfo {
	t.Helper()
	resp, err := hc.Post(url+"/v1/auth/cert/login", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("cert login POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cert login status %d: %s", resp.StatusCode, body)
	}
	var env struct {
		Auth *api.AuthInfo `json:"auth"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Auth == nil {
		t.Fatalf("decode cert login: %v (%s)", err, body)
	}
	return env.Auth
}
