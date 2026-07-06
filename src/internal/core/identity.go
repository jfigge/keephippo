package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

const (
	entityPrefix     = "core/identity/entity/"
	entityNamePrefix = "core/identity/entity-name/"
	groupPrefix      = "core/identity/group/"
	groupNamePrefix  = "core/identity/group-name/"
	aliasPrefix      = "core/identity/alias/"
)

// Entity is a stable identity that auth-method logins (via aliases) map to.
type Entity struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Policies     []string          `json:"policies"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Disabled     bool              `json:"disabled"`
	CreationTime int64             `json:"creation_time"`
}

// Group is a collection of entities that share policies.
type Group struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Policies        []string `json:"policies"`
	MemberEntityIDs []string `json:"member_entity_ids"`
	CreationTime    int64    `json:"creation_time"`
}

// entityAlias links (mount_accessor, name) to a canonical entity.
type entityAlias struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	CanonicalID   string `json:"canonical_id"`
	MountAccessor string `json:"mount_accessor"`
}

func aliasKey(mountAccessor, name string) string {
	sum := sha256.Sum256([]byte(mountAccessor + "|" + name))
	return aliasPrefix + hex.EncodeToString(sum[:])
}

// resolveIdentity maps a login alias to its entity and the policies contributed
// by the entity and every group it belongs to. Returns ("", nil) when the alias
// is unknown or the entity is disabled.
func (c *Core) resolveIdentity(mountAccessor, aliasName string) (string, []string, error) {
	if mountAccessor == "" || aliasName == "" {
		return "", nil, nil
	}
	e, err := c.barrier.Get(aliasKey(mountAccessor, aliasName))
	if err != nil || e == nil {
		return "", nil, err
	}
	var alias entityAlias
	if err := json.Unmarshal(e.Value, &alias); err != nil {
		return "", nil, err
	}
	entity, err := c.loadEntity(alias.CanonicalID)
	if err != nil || entity == nil || entity.Disabled {
		return "", nil, err
	}
	policies := append([]string{}, entity.Policies...)
	groups, err := c.allGroups()
	if err != nil {
		return "", nil, err
	}
	for _, g := range groups {
		if containsString(g.MemberEntityIDs, entity.ID) {
			policies = append(policies, g.Policies...)
		}
	}
	return entity.ID, policies, nil
}

// handleIdentity services identity/* endpoints.
func (c *Core) handleIdentity(req *logical.Request) (*logical.Response, error) {
	sub := strings.TrimPrefix(req.Path, "identity/")
	switch {
	case sub == "entity":
		return c.identityEntity(req)
	case strings.HasPrefix(sub, "entity/id/"):
		return c.identityEntityByID(req, strings.TrimPrefix(sub, "entity/id/"))
	case strings.HasPrefix(sub, "entity/name/"):
		return c.identityEntityByName(strings.TrimPrefix(sub, "entity/name/"))
	case sub == "entity-alias":
		return c.identityAlias(req)
	case sub == "group":
		return c.identityGroup(req)
	case strings.HasPrefix(sub, "group/id/"):
		return c.identityGroupByID(req, strings.TrimPrefix(sub, "group/id/"))
	case strings.HasPrefix(sub, "group/name/"):
		return c.identityGroupByName(strings.TrimPrefix(sub, "group/name/"))
	default:
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("unsupported path %q", req.Path)}
	}
}

// --- entities ---

func (c *Core) identityEntity(req *logical.Request) (*logical.Response, error) {
	if req.Operation == logical.ListOperation {
		ids, err := c.barrier.List(entityPrefix)
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(ids), nil
	}
	name := stringField(req.Data, "name")
	if name == "" {
		return nil, &CodedError{Status: 400, Message: "entity name is required"}
	}
	// Upsert by name.
	entity, err := c.entityByName(name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		id, err := newUUID()
		if err != nil {
			return nil, err
		}
		entity = &Entity{ID: id, Name: name, CreationTime: c.now()}
	}
	if _, ok := req.Data["policies"]; ok {
		entity.Policies = stringSliceField(req.Data, "policies")
	}
	if m := stringMapField(req.Data, "metadata"); m != nil {
		entity.Metadata = m
	}
	if _, ok := req.Data["disabled"]; ok {
		entity.Disabled = boolField(req.Data, "disabled", false)
	}
	if err := c.saveEntity(entity); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"id": entity.ID, "name": entity.Name}}, nil
}

func (c *Core) identityEntityByID(req *logical.Request, id string) (*logical.Response, error) {
	switch req.Operation {
	case logical.ReadOperation:
		e, err := c.loadEntity(id)
		if err != nil || e == nil {
			return nil, err
		}
		return &logical.Response{Data: entityData(e)}, nil
	case logical.DeleteOperation:
		e, err := c.loadEntity(id)
		if err != nil {
			return nil, err
		}
		if e != nil {
			_ = c.barrier.Delete(entityNamePrefix + e.Name)
		}
		return nil, c.barrier.Delete(entityPrefix + id)
	default:
		return nil, &CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (c *Core) identityEntityByName(name string) (*logical.Response, error) {
	e, err := c.entityByName(name)
	if err != nil || e == nil {
		return nil, err
	}
	return &logical.Response{Data: entityData(e)}, nil
}

func entityData(e *Entity) map[string]any {
	return map[string]any{
		"id": e.ID, "name": e.Name, "policies": e.Policies,
		"metadata": e.Metadata, "disabled": e.Disabled, "creation_time": e.CreationTime,
	}
}

// --- aliases ---

func (c *Core) identityAlias(req *logical.Request) (*logical.Response, error) {
	name := stringField(req.Data, "name")
	canonicalID := stringField(req.Data, "canonical_id")
	mountAccessor := stringField(req.Data, "mount_accessor")
	if name == "" || canonicalID == "" || mountAccessor == "" {
		return nil, &CodedError{Status: 400, Message: "name, canonical_id, and mount_accessor are required"}
	}
	if e, err := c.loadEntity(canonicalID); err != nil {
		return nil, err
	} else if e == nil {
		return nil, &CodedError{Status: 400, Message: "canonical_id does not reference a valid entity"}
	}
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	alias := &entityAlias{ID: id, Name: name, CanonicalID: canonicalID, MountAccessor: mountAccessor}
	blob, err := json.Marshal(alias)
	if err != nil {
		return nil, err
	}
	if err := c.barrier.Put(&physical.Entry{Key: aliasKey(mountAccessor, name), Value: blob}); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"id": id, "canonical_id": canonicalID}}, nil
}

// --- groups ---

func (c *Core) identityGroup(req *logical.Request) (*logical.Response, error) {
	if req.Operation == logical.ListOperation {
		ids, err := c.barrier.List(groupPrefix)
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(ids), nil
	}
	name := stringField(req.Data, "name")
	if name == "" {
		return nil, &CodedError{Status: 400, Message: "group name is required"}
	}
	g, err := c.groupByName(name)
	if err != nil {
		return nil, err
	}
	if g == nil {
		id, err := newUUID()
		if err != nil {
			return nil, err
		}
		g = &Group{ID: id, Name: name, CreationTime: c.now()}
	}
	if _, ok := req.Data["policies"]; ok {
		g.Policies = stringSliceField(req.Data, "policies")
	}
	if _, ok := req.Data["member_entity_ids"]; ok {
		g.MemberEntityIDs = stringSliceField(req.Data, "member_entity_ids")
	}
	if err := c.saveGroup(g); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{"id": g.ID, "name": g.Name}}, nil
}

func (c *Core) identityGroupByID(req *logical.Request, id string) (*logical.Response, error) {
	switch req.Operation {
	case logical.ReadOperation:
		g, err := c.loadGroup(id)
		if err != nil || g == nil {
			return nil, err
		}
		return &logical.Response{Data: groupData(g)}, nil
	case logical.DeleteOperation:
		g, err := c.loadGroup(id)
		if err != nil {
			return nil, err
		}
		if g != nil {
			_ = c.barrier.Delete(groupNamePrefix + g.Name)
		}
		return nil, c.barrier.Delete(groupPrefix + id)
	default:
		return nil, &CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (c *Core) identityGroupByName(name string) (*logical.Response, error) {
	g, err := c.groupByName(name)
	if err != nil || g == nil {
		return nil, err
	}
	return &logical.Response{Data: groupData(g)}, nil
}

func groupData(g *Group) map[string]any {
	return map[string]any{
		"id": g.ID, "name": g.Name, "policies": g.Policies,
		"member_entity_ids": g.MemberEntityIDs, "creation_time": g.CreationTime,
	}
}

// --- storage helpers ---

func (c *Core) loadEntity(id string) (*Entity, error) {
	e, err := c.barrier.Get(entityPrefix + id)
	if err != nil || e == nil {
		return nil, err
	}
	var out Entity
	if err := json.Unmarshal(e.Value, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Core) entityByName(name string) (*Entity, error) {
	e, err := c.barrier.Get(entityNamePrefix + name)
	if err != nil || e == nil {
		return nil, err
	}
	return c.loadEntity(string(e.Value))
}

func (c *Core) saveEntity(e *Entity) error {
	blob, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := c.barrier.Put(&physical.Entry{Key: entityPrefix + e.ID, Value: blob}); err != nil {
		return err
	}
	return c.barrier.Put(&physical.Entry{Key: entityNamePrefix + e.Name, Value: []byte(e.ID)})
}

func (c *Core) loadGroup(id string) (*Group, error) {
	e, err := c.barrier.Get(groupPrefix + id)
	if err != nil || e == nil {
		return nil, err
	}
	var out Group
	if err := json.Unmarshal(e.Value, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Core) groupByName(name string) (*Group, error) {
	e, err := c.barrier.Get(groupNamePrefix + name)
	if err != nil || e == nil {
		return nil, err
	}
	return c.loadGroup(string(e.Value))
}

func (c *Core) saveGroup(g *Group) error {
	blob, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if err := c.barrier.Put(&physical.Entry{Key: groupPrefix + g.ID, Value: blob}); err != nil {
		return err
	}
	return c.barrier.Put(&physical.Entry{Key: groupNamePrefix + g.Name, Value: []byte(g.ID)})
}

func (c *Core) allGroups() ([]*Group, error) {
	ids, err := c.barrier.List(groupPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]*Group, 0, len(ids))
	for _, id := range ids {
		if strings.HasSuffix(id, "/") {
			continue
		}
		g, err := c.loadGroup(id)
		if err != nil {
			return nil, err
		}
		if g != nil {
			out = append(out, g)
		}
	}
	return out, nil
}

func (c *Core) now() int64 { return time.Now().Unix() }

// stringMapField reads data[key] as a map[string]string.
func stringMapField(data map[string]any, key string) map[string]string {
	raw, ok := data[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
