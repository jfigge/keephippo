package kv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
)

// V2Backend is the KV version 2 (versioned) secrets engine. It layers version
// history, soft-delete/undelete/destroy, per-key metadata, and check-and-set on
// top of a per-mount storage view, using Vault's sub-path convention:
//
//	data/<path>       latest (or ?version=N) secret value
//	metadata/<path>   version history + tunables (max_versions, cas_required, ...)
//	delete/<path>     soft-delete versions
//	undelete/<path>   restore soft-deleted versions
//	destroy/<path>    permanently destroy versions
//	config            mount-wide defaults
//
// Storage layout (relative to the mount view):
//
//	metadata/<path>          JSON keyMetadata
//	versions/<path>/<n>      JSON {"data": {...}}  (the value of version n)
//	config                   JSON mountConfig
type V2Backend struct {
	storage     logical.Storage
	maxVersions int  // mount default from enable-time options
	casRequired bool // mount default from enable-time options
	nowFn       func() time.Time
}

var _ logical.Backend = (*V2Backend)(nil)

// NewV2 returns a KV v2 backend. opts carries the enable-time mount options
// (version, max_versions, cas_required).
func NewV2(storage logical.Storage, opts map[string]any) *V2Backend {
	return &V2Backend{
		storage:     storage,
		maxVersions: logical.FieldInt(opts, "max_versions"),
		casRequired: logical.FieldBool(opts, "cas_required", false),
		nowFn:       time.Now,
	}
}

// versionMeta is the per-version record in a key's metadata.
type versionMeta struct {
	CreatedTime  string `json:"created_time"`
	DeletionTime string `json:"deletion_time"`
	Destroyed    bool   `json:"destroyed"`
}

// keyMetadata is the stored metadata/<path> record.
type keyMetadata struct {
	CurrentVersion int                    `json:"current_version"`
	OldestVersion  int                    `json:"oldest_version"`
	CreatedTime    string                 `json:"created_time"`
	UpdatedTime    string                 `json:"updated_time"`
	MaxVersions    int                    `json:"max_versions"`
	CASRequired    bool                   `json:"cas_required"`
	CustomMetadata map[string]string      `json:"custom_metadata,omitempty"`
	Versions       map[string]versionMeta `json:"versions"`
}

// mountConfig is the stored mount-wide config.
type mountConfig struct {
	MaxVersions        int    `json:"max_versions"`
	CASRequired        bool   `json:"cas_required"`
	DeleteVersionAfter string `json:"delete_version_after,omitempty"`
}

func (b *V2Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	path := req.Path
	switch {
	case path == "config":
		return b.config(req)
	case path == "data" || strings.HasPrefix(path, "data/"):
		return b.data(req, strings.TrimPrefix(path, "data/"))
	case path == "metadata" || strings.HasPrefix(path, "metadata/"):
		return b.metadata(req, strings.TrimPrefix(path, "metadata/"))
	case strings.HasPrefix(path, "delete/"):
		return b.mutateVersions(req, strings.TrimPrefix(path, "delete/"), opSoftDelete)
	case strings.HasPrefix(path, "undelete/"):
		return b.mutateVersions(req, strings.TrimPrefix(path, "undelete/"), opUndelete)
	case strings.HasPrefix(path, "destroy/"):
		return b.mutateVersions(req, strings.TrimPrefix(path, "destroy/"), opDestroy)
	default:
		return nil, &logical.CodedError{Status: 404, Message: fmt.Sprintf("unsupported path %q", path)}
	}
}

// --- data/<path> ---

func (b *V2Backend) data(req *logical.Request, key string) (*logical.Response, error) {
	switch req.Operation {
	case logical.ReadOperation:
		return b.readData(req, key)
	case logical.CreateOperation, logical.UpdateOperation:
		return b.writeData(req, key)
	case logical.DeleteOperation:
		// DELETE data/<path> soft-deletes the latest version.
		return b.mutateVersionsList(key, nil, opSoftDelete)
	default:
		return nil, &logical.CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (b *V2Backend) readData(req *logical.Request, key string) (*logical.Response, error) {
	md, err := b.loadMeta(key)
	if err != nil || md == nil {
		return nil, err // 404
	}
	ver := md.CurrentVersion
	if q := req.QueryValue("version"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			ver = n
		}
	}
	vm, ok := md.Versions[strconv.Itoa(ver)]
	if !ok {
		return nil, nil // 404: no such version
	}
	out := map[string]any{"metadata": versionMetaResponse(ver, vm, md.CustomMetadata)}
	if vm.Destroyed || vm.DeletionTime != "" {
		out["data"] = nil // deleted/destroyed: metadata only
		return &logical.Response{Data: out}, nil
	}
	data, err := b.loadVersionData(key, ver)
	if err != nil {
		return nil, err
	}
	out["data"] = data
	return &logical.Response{Data: out}, nil
}

func (b *V2Backend) writeData(req *logical.Request, key string) (*logical.Response, error) {
	payload := logical.FieldMap(req.Data, "data")
	if payload == nil {
		payload = map[string]any{}
	}
	opts := logical.FieldMap(req.Data, "options")

	md, err := b.loadMeta(key)
	if err != nil {
		return nil, err
	}
	if md == nil {
		md = b.newMeta()
	}

	// Check-and-set.
	casRequired := b.casRequired || md.CASRequired
	if cfg, _ := b.loadConfig(); cfg != nil && cfg.CASRequired {
		casRequired = true
	}
	_, hasCAS := opts["cas"]
	if hasCAS {
		if cas := logical.FieldInt(opts, "cas"); cas != md.CurrentVersion {
			return nil, &logical.CodedError{Status: 400, Message: fmt.Sprintf(
				"check-and-set parameter did not match the current version; supplied %d, stored %d", cas, md.CurrentVersion,
			)}
		}
	} else if casRequired {
		return nil, &logical.CodedError{Status: 400, Message: "check-and-set parameter required for this call"}
	}

	now := b.now()
	ver := md.CurrentVersion + 1
	if err := b.saveVersionData(key, ver, payload); err != nil {
		return nil, err
	}
	md.Versions[strconv.Itoa(ver)] = versionMeta{CreatedTime: now}
	md.CurrentVersion = ver
	md.UpdatedTime = now
	if md.CreatedTime == "" {
		md.CreatedTime = now
	}
	if md.OldestVersion == 0 {
		md.OldestVersion = 1
	}
	b.evict(key, md)
	if err := b.saveMeta(key, md); err != nil {
		return nil, err
	}
	return &logical.Response{Data: versionMetaResponse(ver, md.Versions[strconv.Itoa(ver)], md.CustomMetadata)}, nil
}

// evict enforces the effective max_versions by permanently removing the oldest
// versions' data (their metadata slot is dropped too).
func (b *V2Backend) evict(key string, md *keyMetadata) {
	max := b.effectiveMaxVersions(md)
	if max <= 0 {
		return
	}
	for md.CurrentVersion-md.OldestVersion+1 > max {
		old := strconv.Itoa(md.OldestVersion)
		_ = b.storage.Delete(versionKey(key, md.OldestVersion))
		delete(md.Versions, old)
		md.OldestVersion++
	}
}

// effectiveMaxVersions resolves the version cap: the per-key metadata value wins,
// then the persisted mount config, then the enable-time mount default. 0 = keep
// all versions.
func (b *V2Backend) effectiveMaxVersions(md *keyMetadata) int {
	if md != nil && md.MaxVersions > 0 {
		return md.MaxVersions
	}
	if cfg, _ := b.loadConfig(); cfg != nil && cfg.MaxVersions > 0 {
		return cfg.MaxVersions
	}
	return b.maxVersions
}

// --- metadata/<path> ---

func (b *V2Backend) metadata(req *logical.Request, key string) (*logical.Response, error) {
	switch req.Operation {
	case logical.ListOperation:
		keys, err := b.storage.List("metadata/" + key)
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(keys), nil
	case logical.ReadOperation:
		md, err := b.loadMeta(key)
		if err != nil || md == nil {
			return nil, err // 404
		}
		return &logical.Response{Data: b.metaResponse(md)}, nil
	case logical.CreateOperation, logical.UpdateOperation:
		return b.writeMetadata(req, key)
	case logical.DeleteOperation:
		return nil, b.purge(key)
	default:
		return nil, &logical.CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (b *V2Backend) writeMetadata(req *logical.Request, key string) (*logical.Response, error) {
	md, err := b.loadMeta(key)
	if err != nil {
		return nil, err
	}
	if md == nil {
		md = b.newMeta()
	}
	if _, ok := req.Data["max_versions"]; ok {
		md.MaxVersions = logical.FieldInt(req.Data, "max_versions")
	}
	if _, ok := req.Data["cas_required"]; ok {
		md.CASRequired = logical.FieldBool(req.Data, "cas_required", false)
	}
	if cm := logical.FieldStringMap(req.Data, "custom_metadata"); cm != nil {
		md.CustomMetadata = cm
	}
	// Applying a tighter max_versions may evict existing versions.
	b.evict(key, md)
	return nil, b.saveMeta(key, md)
}

// purge removes every version's data and the metadata record (hard delete).
func (b *V2Backend) purge(key string) error {
	md, err := b.loadMeta(key)
	if err != nil {
		return err
	}
	if md != nil {
		for vs := range md.Versions {
			if n, err := strconv.Atoi(vs); err == nil {
				_ = b.storage.Delete(versionKey(key, n))
			}
		}
	}
	return b.storage.Delete(metaKey(key))
}

// --- delete / undelete / destroy ---

type versionOp int

const (
	opSoftDelete versionOp = iota
	opUndelete
	opDestroy
)

func (b *V2Backend) mutateVersions(req *logical.Request, key string, op versionOp) (*logical.Response, error) {
	return b.mutateVersionsList(key, logical.FieldIntSlice(req.Data, "versions"), op)
}

func (b *V2Backend) mutateVersionsList(key string, versions []int, op versionOp) (*logical.Response, error) {
	md, err := b.loadMeta(key)
	if err != nil || md == nil {
		return nil, err
	}
	if len(versions) == 0 {
		versions = []int{md.CurrentVersion} // default to the latest version
	}
	now := b.now()
	for _, n := range versions {
		vs := strconv.Itoa(n)
		vm, ok := md.Versions[vs]
		if !ok {
			continue
		}
		switch op {
		case opSoftDelete:
			if !vm.Destroyed {
				vm.DeletionTime = now
			}
		case opUndelete:
			if !vm.Destroyed {
				vm.DeletionTime = ""
			}
		case opDestroy:
			vm.Destroyed = true
			vm.DeletionTime = ""
			_ = b.storage.Delete(versionKey(key, n))
		}
		md.Versions[vs] = vm
	}
	return nil, b.saveMeta(key, md)
}

// --- config ---

func (b *V2Backend) config(req *logical.Request) (*logical.Response, error) {
	switch req.Operation {
	case logical.ReadOperation:
		cfg, err := b.loadConfig()
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			cfg = &mountConfig{MaxVersions: b.maxVersions, CASRequired: b.casRequired}
		}
		return &logical.Response{Data: map[string]any{
			"max_versions":         cfg.MaxVersions,
			"cas_required":         cfg.CASRequired,
			"delete_version_after": cfg.DeleteVersionAfter,
		}}, nil
	case logical.CreateOperation, logical.UpdateOperation:
		cfg, _ := b.loadConfig()
		if cfg == nil {
			cfg = &mountConfig{MaxVersions: b.maxVersions, CASRequired: b.casRequired}
		}
		if _, ok := req.Data["max_versions"]; ok {
			cfg.MaxVersions = logical.FieldInt(req.Data, "max_versions")
		}
		if _, ok := req.Data["cas_required"]; ok {
			cfg.CASRequired = logical.FieldBool(req.Data, "cas_required", false)
		}
		if v := logical.FieldString(req.Data, "delete_version_after"); v != "" {
			cfg.DeleteVersionAfter = v
		}
		blob, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		return nil, b.storage.Put(&logical.StorageEntry{Key: "config", Value: blob})
	default:
		return nil, &logical.CodedError{Status: 405, Message: "unsupported operation"}
	}
}

// --- response shaping ---

func versionMetaResponse(ver int, vm versionMeta, custom map[string]string) map[string]any {
	return map[string]any{
		"version":         ver,
		"created_time":    vm.CreatedTime,
		"deletion_time":   vm.DeletionTime,
		"destroyed":       vm.Destroyed,
		"custom_metadata": custom,
	}
}

func (b *V2Backend) metaResponse(md *keyMetadata) map[string]any {
	versions := map[string]any{}
	for vs, vm := range md.Versions {
		versions[vs] = map[string]any{
			"created_time":  vm.CreatedTime,
			"deletion_time": vm.DeletionTime,
			"destroyed":     vm.Destroyed,
		}
	}
	return map[string]any{
		"current_version": md.CurrentVersion,
		"oldest_version":  md.OldestVersion,
		"created_time":    md.CreatedTime,
		"updated_time":    md.UpdatedTime,
		"max_versions":    md.MaxVersions,
		"cas_required":    md.CASRequired,
		"custom_metadata": md.CustomMetadata,
		"versions":        versions,
	}
}

// --- storage helpers ---

func (b *V2Backend) newMeta() *keyMetadata {
	return &keyMetadata{Versions: map[string]versionMeta{}}
}

func (b *V2Backend) loadMeta(key string) (*keyMetadata, error) {
	e, err := b.storage.Get(metaKey(key))
	if err != nil || e == nil {
		return nil, err
	}
	var md keyMetadata
	if err := json.Unmarshal(e.Value, &md); err != nil {
		return nil, err
	}
	if md.Versions == nil {
		md.Versions = map[string]versionMeta{}
	}
	return &md, nil
}

func (b *V2Backend) saveMeta(key string, md *keyMetadata) error {
	blob, err := json.Marshal(md)
	if err != nil {
		return err
	}
	return b.storage.Put(&logical.StorageEntry{Key: metaKey(key), Value: blob})
}

func (b *V2Backend) loadVersionData(key string, ver int) (map[string]any, error) {
	e, err := b.storage.Get(versionKey(key, ver))
	if err != nil || e == nil {
		return nil, err
	}
	var wrap struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(e.Value, &wrap); err != nil {
		return nil, err
	}
	return wrap.Data, nil
}

func (b *V2Backend) saveVersionData(key string, ver int, data map[string]any) error {
	blob, err := json.Marshal(struct {
		Data map[string]any `json:"data"`
	}{Data: data})
	if err != nil {
		return err
	}
	return b.storage.Put(&logical.StorageEntry{Key: versionKey(key, ver), Value: blob})
}

func (b *V2Backend) loadConfig() (*mountConfig, error) {
	e, err := b.storage.Get("config")
	if err != nil || e == nil {
		return nil, err
	}
	var cfg mountConfig
	if err := json.Unmarshal(e.Value, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (b *V2Backend) now() string { return b.nowFn().UTC().Format(time.RFC3339Nano) }

func metaKey(key string) string             { return "metadata/" + key }
func versionKey(key string, ver int) string { return "versions/" + key + "/" + strconv.Itoa(ver) }

// sortedVersionNums returns a key's version numbers in ascending order (helper
// for tests / callers that need deterministic ordering).
func sortedVersionNums(md *keyMetadata) []int {
	out := make([]int, 0, len(md.Versions))
	for vs := range md.Versions {
		if n, err := strconv.Atoi(vs); err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}
