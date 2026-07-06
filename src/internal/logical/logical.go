// Package logical defines the interface between the core request router and the
// secrets engines / auth methods that plug into it. A request is
// (operation, path, data, token); a backend handles it against a Storage view
// that the core scopes and encrypts per mount.
//
// This is a minimal, clean-room abstraction shaped like Vault's, deliberately
// independent of the OpenBao SDK's gRPC plugin framework.
package logical

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
}

// Response is a backend's reply. A nil Response means "no data": for a read it
// is a not-found (404); for a write/delete it is success with no content (204).
type Response struct {
	Data map[string]any
	Auth *Auth
}

// Auth is the authentication result returned by token creation and login,
// rendered into the envelope's "auth" field.
type Auth struct {
	ClientToken   string   `json:"client_token"`
	Accessor      string   `json:"accessor"`
	Policies      []string `json:"policies"`
	TokenPolicies []string `json:"token_policies"`
	LeaseDuration int64    `json:"lease_duration"`
	Renewable     bool     `json:"renewable"`
}

// Backend is a secrets engine or auth method.
type Backend interface {
	HandleRequest(req *Request) (*Response, error)
}

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
