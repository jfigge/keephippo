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
	case strings.HasPrefix(sub, "mounts/"):
		name := strings.TrimPrefix(sub, "mounts/")
		if req.Operation == logical.DeleteOperation {
			return nil, c.DisableMount(name)
		}
		return nil, c.EnableMount(name, stringField(req.Data, "type"))
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

func (c *Core) sysListMounts() (*logical.Response, error) {
	data := map[string]any{}
	for _, m := range c.ListMounts() {
		data[m.Path] = map[string]any{"type": m.Type, "accessor": m.Accessor, "uuid": m.UUID}
	}
	return &logical.Response{Data: data}, nil
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
