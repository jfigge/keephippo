// Package logical defines the interface between the core request router and the
// secrets engines / auth methods that plug into it. A request is
// (operation, path, data, token); a backend handles it against a Storage view
// that the core scopes and encrypts per mount.
//
// This is a minimal, clean-room abstraction shaped like Vault's, deliberately
// independent of the OpenBao SDK's gRPC plugin framework.
package logical

import "net/url"

// Operation is the verb of a request, derived from the HTTP method.
type Operation string

const (
	CreateOperation Operation = "create"
	ReadOperation   Operation = "read"
	UpdateOperation Operation = "update"
	DeleteOperation Operation = "delete"
	ListOperation   Operation = "list"
)

// Request is a single operation routed to a backend. Path is relative to the
// backend's mount point.
type Request struct {
	Operation   Operation
	Path        string
	Data        map[string]any
	ClientToken string
	Storage     Storage
	// Query carries the URL query string (e.g. ?version=3), used by KV v2 reads.
	Query url.Values
}

// QueryValue returns the first value for a query parameter, or "".
func (r *Request) QueryValue(key string) string {
	if r.Query == nil {
		return ""
	}
	return r.Query.Get(key)
}

// Response is a backend's reply. A nil Response means "no data": for a read it
// is a not-found (404); for a write/delete it is success with no content (204).
type Response struct {
	Data map[string]any
	Auth *Auth
}

// Auth is the authentication result returned by token creation and login,
// rendered into the envelope's "auth" field.
//
// An auth-method backend returns an Auth from a login with the credential-bound
// fields set (Policies, LeaseDuration, DisplayName, NumUses, Metadata) but
// leaves ClientToken/Accessor empty: the core mints the real token and fills
// those in. Token creation, by contrast, returns a fully-populated Auth.
type Auth struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	TokenPolicies []string          `json:"token_policies"`
	LeaseDuration int64             `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	DisplayName   string            `json:"display_name,omitempty"`
	NumUses       int               `json:"num_uses,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Backend is a secrets engine or auth method.
type Backend interface {
	HandleRequest(req *Request) (*Response, error)
}

// Unauthenticated is implemented by auth-method backends to declare which of
// their paths (relative to the mount) may be reached without a client token —
// i.e. the login paths. The core consults it before enforcing the token guard
// and ACL, and mints a token from the resulting Auth block.
type Unauthenticated interface {
	IsUnauthenticated(op Operation, path string) bool
}

// CodedError carries an HTTP status alongside a message so a backend can signal
// a specific wire status (e.g. 400 for a bad credential or a CAS mismatch)
// without importing the core package. The HTTP layer translates it like
// core.CodedError.
type CodedError struct {
	Status  int
	Message string
}

func (e *CodedError) Error() string { return e.Message }

// StorageEntry is a key/value pair within a backend's storage view.
type StorageEntry struct {
	Key   string
	Value []byte
}

// Storage is a backend's private, per-mount view of encrypted storage. Get
// returns (nil, nil) when the key is absent.
type Storage interface {
	Get(key string) (*StorageEntry, error)
	Put(entry *StorageEntry) error
	Delete(key string) error
	List(prefix string) ([]string, error)
}

// ListResponse builds the conventional list reply: {"keys": [...]}.
func ListResponse(keys []string) *Response {
	return &Response{Data: map[string]any{"keys": keys}}
}
