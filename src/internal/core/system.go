package core

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/policy"
)

// handleSystem services the sys/* control-plane endpoints (mounts, remount,
// seal, ACL policies, capabilities). The token has already been authorized.
func (c *Core) handleSystem(req *logical.Request, te *TokenEntry) (*logical.Response, error) {
	sub := strings.TrimPrefix(req.Path, "sys/")
	switch {
	case sub == "mounts":
		return c.sysListMounts()
	case strings.HasPrefix(sub, "mounts/") && strings.HasSuffix(sub, "/tune"):
		return c.sysTune(req, strings.TrimSuffix(strings.TrimPrefix(sub, "mounts/"), "/tune"))
	case strings.HasPrefix(sub, "internal/ui/mounts/"):
		return c.sysInternalUIMount(strings.TrimPrefix(sub, "internal/ui/mounts/"))
	case sub == "internal/ui/mounts":
		return c.sysListMounts()
	case strings.HasPrefix(sub, "mounts/"):
		name := strings.TrimPrefix(sub, "mounts/")
		if req.Operation == logical.DeleteOperation {
			return nil, c.DisableMount(name)
		}
		return nil, c.EnableMount(name, stringField(req.Data, "type"), mapField(req.Data, "options"))
	case sub == "auth":
		return c.sysListAuth(), nil
	case strings.HasPrefix(sub, "auth/"):
		name := strings.TrimPrefix(sub, "auth/")
		if req.Operation == logical.DeleteOperation {
			return nil, c.DisableAuth(name)
		}
		return nil, c.EnableAuth(name, stringField(req.Data, "type"))
	case sub == "leases/lookup":
		return c.sysLeaseLookup(req)
	case strings.HasPrefix(sub, "leases/lookup/"):
		return c.sysLeaseList(strings.TrimPrefix(sub, "leases/lookup/"))
	case sub == "leases/renew" || strings.HasPrefix(sub, "leases/renew/"):
		return c.sysLeaseRenew(req)
	case strings.HasPrefix(sub, "leases/revoke-prefix/"):
		return c.sysLeaseRevokePrefix(strings.TrimPrefix(sub, "leases/revoke-prefix/"))
	case strings.HasPrefix(sub, "leases/revoke-force/"):
		return c.sysLeaseRevokePrefix(strings.TrimPrefix(sub, "leases/revoke-force/"))
	case sub == "leases/revoke" || strings.HasPrefix(sub, "leases/revoke/"):
		return c.sysLeaseRevoke(req, strings.TrimPrefix(sub, "leases/revoke/"))
	case sub == "audit":
		return &logical.Response{Data: map[string]any{}}, nil
	case strings.HasPrefix(sub, "audit/"):
		return nil, &CodedError{Status: 400, Message: "audit devices are not yet supported (Phase 7)"}
	case sub == "remount":
		return nil, c.Remount(stringField(req.Data, "from"), stringField(req.Data, "to"))
	case sub == "seal":
		return nil, c.Seal()
	case sub == "policies/acl" || sub == "policy":
		return c.sysListPolicies()
	case strings.HasPrefix(sub, "policies/acl/"):
		return c.sysPolicy(req, strings.TrimPrefix(sub, "policies/acl/"))
	case strings.HasPrefix(sub, "policy/"):
		return c.sysPolicy(req, strings.TrimPrefix(sub, "policy/"))
	case sub == "capabilities-self":
		acl, err := c.aclFor(te)
		if err != nil {
			return nil, err
		}
		return capabilitiesResponse(acl, req.Data), nil
	case sub == "capabilities":
		return c.sysCapabilitiesToken(req)
	default:
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("unsupported path %q", req.Path)}
	}
}

func (c *Core) sysLeaseLookup(req *logical.Request) (*logical.Response, error) {
	id := stringField(req.Data, "lease_id")
	if id == "" {
		return nil, &CodedError{Status: 400, Message: "missing lease_id"}
	}
	data, err := c.expiration.lookup(id)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}

func (c *Core) sysLeaseList(prefix string) (*logical.Response, error) {
	keys, err := c.expiration.listPrefix(prefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func (c *Core) sysLeaseRenew(req *logical.Request) (*logical.Response, error) {
	id := stringField(req.Data, "lease_id")
	if id == "" {
		return nil, &CodedError{Status: 400, Message: "missing lease_id"}
	}
	ttl, err := c.expiration.renew(id, durationField(req.Data, "increment"))
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"lease_id":       id,
		"lease_duration": ttl,
		"renewable":      true,
	}}, nil
}

func (c *Core) sysLeaseRevoke(req *logical.Request, pathID string) (*logical.Response, error) {
	id := pathID
	if id == "" {
		id = stringField(req.Data, "lease_id")
	}
	if id == "" {
		return nil, &CodedError{Status: 400, Message: "missing lease_id"}
	}
	return nil, c.expiration.revoke(id)
}

func (c *Core) sysLeaseRevokePrefix(prefix string) (*logical.Response, error) {
	if prefix == "" {
		return nil, &CodedError{Status: 400, Message: "missing prefix"}
	}
	if _, err := c.expiration.revokePrefix(prefix); err != nil {
		return nil, err
	}
	return nil, nil
}

func (c *Core) sysListMounts() (*logical.Response, error) {
	data := map[string]any{}
	for _, m := range c.ListMounts() {
		data[m.Path] = mountInfo(m)
	}
	return &logical.Response{Data: data}, nil
}

// sysInternalUIMount resolves the mount serving path (longest-prefix match) and
// returns its entry — including options.version — so a Vault/OpenBao `kv` CLI
// can auto-detect whether the mount is KV v1 or v2.
func (c *Core) sysInternalUIMount(path string) (*logical.Response, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var best *MountEntry
	for _, m := range c.mounts.Entries {
		root := strings.TrimSuffix(m.Path, "/")
		if path == root || strings.HasPrefix(path, m.Path) {
			if best == nil || len(m.Path) > len(best.Path) {
				best = m
			}
		}
	}
	if best == nil {
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("preflight capability check returned 403, no mount for path %q", path)}
	}
	return &logical.Response{Data: mountInfo(best)}, nil
}

// mountInfo renders a mount entry as Vault's per-mount description map.
func mountInfo(m *MountEntry) map[string]any {
	opts := m.Options
	if opts == nil {
		opts = map[string]any{}
	}
	return map[string]any{
		"path":        m.Path,
		"type":        m.Type,
		"description": m.Description,
		"accessor":    m.Accessor,
		"uuid":        m.UUID,
		"options":     opts,
		"local":       false,
	}
}

func (c *Core) sysListAuth() *logical.Response {
	data := map[string]any{}
	for _, m := range c.ListAuth() {
		data[m.Path] = map[string]any{"type": m.Type, "accessor": m.Accessor}
	}
	return &logical.Response{Data: data}
}

func (c *Core) sysTune(req *logical.Request, name string) (*logical.Response, error) {
	if req.Operation == logical.ReadOperation {
		cfg, err := c.MountConfig(name)
		if err != nil {
			return nil, err
		}
		return &logical.Response{Data: cfg}, nil
	}
	return nil, c.TuneMount(name, req.Data)
}

func (c *Core) sysListPolicies() (*logical.Response, error) {
	names, err := c.policies.list()
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{"root": {}}
	for _, n := range names {
		set[strings.TrimSuffix(n, "/")] = struct{}{}
	}
	keys := sortedSet(set)
	return &logical.Response{Data: map[string]any{"keys": keys, "policies": keys}}, nil
}

func (c *Core) sysPolicy(req *logical.Request, name string) (*logical.Response, error) {
	if name == "" {
		return nil, &CodedError{Status: 400, Message: "missing policy name"}
	}
	switch req.Operation {
	case logical.ReadOperation:
		if name == "root" {
			return &logical.Response{Data: map[string]any{"name": "root", "policy": "", "rules": ""}}, nil
		}
		txt, ok, err := c.policies.text(name)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil // 404
		}
		return &logical.Response{Data: map[string]any{"name": name, "policy": txt, "rules": txt}}, nil
	case logical.CreateOperation, logical.UpdateOperation:
		if name == "root" {
			return nil, &CodedError{Status: 400, Message: "cannot update the root policy"}
		}
		rules := stringField(req.Data, "policy")
		if rules == "" {
			rules = stringField(req.Data, "rules")
		}
		return nil, c.policies.set(name, rules)
	case logical.DeleteOperation:
		if name == "root" || name == "default" {
			return nil, &CodedError{Status: 400, Message: "cannot delete the " + name + " policy"}
		}
		return nil, c.policies.delete(name)
	default:
		return nil, &CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (c *Core) sysCapabilitiesToken(req *logical.Request) (*logical.Response, error) {
	tok := stringField(req.Data, "token")
	if tok == "" {
		return nil, &CodedError{Status: 400, Message: "missing token"}
	}
	te, err := c.tokens.lookup(tok)
	if err != nil {
		return nil, err
	}
	if te == nil {
		return nil, &CodedError{Status: 400, Message: "invalid token"}
	}
	acl, err := c.aclFor(te)
	if err != nil {
		return nil, err
	}
	return capabilitiesResponse(acl, req.Data), nil
}

func capabilitiesResponse(acl *policy.ACL, data map[string]any) *logical.Response {
	paths := stringSliceField(data, "paths")
	if len(paths) == 0 {
		if p := stringField(data, "path"); p != "" {
			paths = []string{p}
		}
	}
	out := map[string]any{}
	for _, p := range paths {
		out[p] = acl.Capabilities(p)
	}
	if len(paths) == 1 {
		out["capabilities"] = acl.Capabilities(paths[0])
	}
	return &logical.Response{Data: out}
}

// --- request-data field helpers ---

func stringField(data map[string]any, key string) string {
	v, _ := data[key].(string)
	return v
}

func mapField(data map[string]any, key string) map[string]any {
	m, _ := data[key].(map[string]any)
	return m
}

func boolField(data map[string]any, key string, def bool) bool {
	if v, ok := data[key].(bool); ok {
		return v
	}
	return def
}

func intField(data map[string]any, key string) int {
	switch v := data[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func stringSliceField(data map[string]any, key string) []string {
	switch v := data[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return strings.Split(v, ",")
	}
	return nil
}

func durationField(data map[string]any, key string) time.Duration {
	switch v := data[key].(type) {
	case string:
		if v == "" {
			return 0
		}
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	case float64:
		return time.Duration(v) * time.Second
	case int:
		return time.Duration(v) * time.Second
	}
	return 0
}

func sortedSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
