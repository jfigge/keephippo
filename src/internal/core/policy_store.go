package core

import (
	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical"
	"github.com/jfigge/keephippo/internal/policy"
)

const policyPrefix = "core/policy/acl/"

// defaultPolicyHCL is the built-in "default" policy attached to non-root tokens:
// it permits a token to manage itself and to run the mount-version preflight the
// KV CLI relies on (matching Vault's default policy).
const defaultPolicyHCL = `
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self"  { capabilities = ["update"] }
path "sys/internal/ui/mounts"    { capabilities = ["read"] }
path "sys/internal/ui/mounts/*"  { capabilities = ["read"] }
`

// policyStore persists ACL policy source (HCL text) through the barrier.
type policyStore struct {
	barrier *barrier.Barrier
}

func newPolicyStore(b *barrier.Barrier) *policyStore {
	return &policyStore{barrier: b}
}

func policyKey(name string) string { return policyPrefix + name }

// set validates and stores the HCL source for a named policy.
func (ps *policyStore) set(name, rules string) error {
	if _, err := policy.Parse(name, rules); err != nil {
		return &CodedError{Status: 400, Message: err.Error()}
	}
	return ps.barrier.Put(&physical.Entry{Key: policyKey(name), Value: []byte(rules)})
}

// text returns the stored HCL source for name, or ("", false, nil) if absent.
func (ps *policyStore) text(name string) (string, bool, error) {
	e, err := ps.barrier.Get(policyKey(name))
	if err != nil || e == nil {
		return "", false, err
	}
	return string(e.Value), true, nil
}

// policy parses and returns the named policy, or (nil, nil) if it does not exist.
func (ps *policyStore) policy(name string) (*policy.Policy, error) {
	txt, ok, err := ps.text(name)
	if err != nil || !ok {
		return nil, err
	}
	return policy.Parse(name, txt)
}

func (ps *policyStore) list() ([]string, error) {
	return ps.barrier.List(policyPrefix)
}

func (ps *policyStore) delete(name string) error {
	return ps.barrier.Delete(policyKey(name))
}

// aclFor builds the effective ACL for a token from its policies. A root token
// (or the "root" policy name) yields an unrestricted ACL; unknown policy names
// are skipped (they grant nothing).
func (c *Core) aclFor(te *TokenEntry) (*policy.ACL, error) {
	if te.IsRoot() {
		return policy.NewACL([]*policy.Policy{{Name: "root"}}), nil
	}
	pols := make([]*policy.Policy, 0, len(te.Policies))
	for _, name := range te.Policies {
		p, err := c.policies.policy(name)
		if err != nil {
			return nil, err
		}
		if p != nil {
			pols = append(pols, p)
		}
	}
	return policy.NewACL(pols), nil
}
