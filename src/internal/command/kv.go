package command

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/api"
)

// newKVCmd builds the `kv` command tree. It transparently supports KV v1 and v2:
// it queries sys/internal/ui/mounts/<path> to detect the mount version and, for
// v2 mounts, rewrites requests onto the data/ and metadata/ sub-paths.
func newKVCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kv",
		Short: "Interact with the KV secrets engine (v1 and v2)",
	}
	cmd.AddCommand(
		newKVGetCmd(),
		newKVPutCmd(),
		newKVListCmd(),
		newKVDeleteCmd(),
		newKVUndeleteCmd(),
		newKVDestroyCmd(),
		newKVPatchCmd(),
		newKVRollbackCmd(),
		newKVMetadataCmd(),
	)
	return cmd
}

// kvMount describes how to address a path for a mount.
type kvMount struct {
	mount string // e.g. "secret/"
	rel   string // path relative to the mount, e.g. "foo"
	v2    bool
}

func (m kvMount) dataPath() string     { return m.mount + "data/" + m.rel }
func (m kvMount) metadataPath() string { return m.mount + "metadata/" + m.rel }
func (m kvMount) subPath(sub string) string {
	return m.mount + sub + "/" + m.rel
}

// resolveKVMount detects the mount serving path and whether it is KV v2. If the
// preflight lookup fails (e.g. an older server), it falls back to treating the
// path as a v1 mount so plain reads/writes still work.
func resolveKVMount(c *api.Client, path string) kvMount {
	path = strings.TrimPrefix(path, "/")
	resp, err := c.Do(http.MethodGet, "/v1/sys/internal/ui/mounts/"+path, nil)
	if err != nil || resp.Data == nil {
		return kvMount{mount: firstSegment(path), rel: relTo(path, firstSegment(path))}
	}
	mount, _ := resp.Data["path"].(string)
	if mount == "" {
		mount = firstSegment(path)
	}
	v2 := false
	if opts, ok := resp.Data["options"].(map[string]any); ok {
		if v, _ := opts["version"].(string); v == "2" {
			v2 = true
		}
	}
	return kvMount{mount: mount, rel: relTo(path, mount), v2: v2}
}

func firstSegment(path string) string {
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i+1]
	}
	return path + "/"
}

func relTo(path, mount string) string {
	return strings.TrimPrefix(path, strings.TrimSuffix(mount, "/")+"/")
}

// --- get ---

func newKVGetCmd() *cobra.Command {
	var version int
	cmd := &cobra.Command{
		Use:   "get [-version=N] PATH",
		Short: "Read a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			m := resolveKVMount(c, args[0])
			reqPath := "/v1/" + args[0]
			if m.v2 {
				reqPath = "/v1/" + m.dataPath()
				if version > 0 {
					reqPath += "?version=" + strconv.Itoa(version)
				}
			}
			resp, err := c.Do(http.MethodGet, reqPath, nil)
			if err != nil {
				if resp != nil && resp.StatusCode == http.StatusNotFound {
					return noValue(args[0])
				}
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				if m.v2 {
					kvV2GetTable(w, resp.Data)
				} else {
					kvTable(w, resp.Data)
				}
			})
		},
	}
	cmd.Flags().IntVar(&version, "version", 0, "Specific version to read (KV v2)")
	return cmd
}

// --- put ---

func newKVPutCmd() *cobra.Command {
	var cas int
	cmd := &cobra.Command{
		Use:   "put [-cas=N] PATH KEY=VALUE...",
		Short: "Write a secret",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			data, err := parseKV(args[1:])
			if err != nil {
				return err
			}
			m := resolveKVMount(c, args[0])
			reqPath := "/v1/" + args[0]
			body := data
			if m.v2 {
				reqPath = "/v1/" + m.dataPath()
				body = map[string]any{"data": data}
				if cmd.Flags().Changed("cas") {
					body["options"] = map[string]any{"cas": cas}
				}
			}
			resp, err := c.Do(http.MethodPut, reqPath, body)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				fmt.Fprintf(w, "Success! Data written to: %s\n", args[0])
				if v, ok := resp.Data["version"]; ok {
					fmt.Fprintf(w, "%-16s%v\n", "version", v)
				}
			})
		},
	}
	cmd.Flags().IntVar(&cas, "cas", 0, "Check-and-set: only write if the current version matches (KV v2)")
	return cmd
}

// --- list ---

func newKVListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list PATH",
		Short: "List secret keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			m := resolveKVMount(c, args[0])
			reqPath := "/v1/" + args[0]
			if m.v2 {
				reqPath = "/v1/" + m.metadataPath()
			}
			resp, err := c.Do("LIST", reqPath, nil)
			if err != nil {
				if resp != nil && resp.StatusCode == http.StatusNotFound {
					return noValue(args[0])
				}
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { keysTable(w, resp.Data) })
		},
	}
}

// --- delete ---

func newKVDeleteCmd() *cobra.Command {
	var versions string
	cmd := &cobra.Command{
		Use:   "delete [-versions=1,2] PATH",
		Short: "Delete a secret (soft-delete versions for KV v2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			m := resolveKVMount(c, args[0])
			if !m.v2 {
				if _, err := c.Do(http.MethodDelete, "/v1/"+args[0], nil); err != nil {
					return err
				}
				success(cmd, "Success! Data deleted (if it existed) at: %s\n", args[0])
				return nil
			}
			if vs := parseVersions(versions); len(vs) > 0 {
				if _, err := c.Do(http.MethodPut, "/v1/"+m.subPath("delete"), map[string]any{"versions": vs}); err != nil {
					return err
				}
			} else if _, err := c.Do(http.MethodDelete, "/v1/"+m.dataPath(), nil); err != nil {
				return err
			}
			success(cmd, "Success! Data deleted (if it existed) at: %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&versions, "versions", "", "Comma-separated versions to soft-delete (KV v2)")
	return cmd
}

// --- undelete / destroy ---

func newKVUndeleteCmd() *cobra.Command {
	var versions string
	cmd := &cobra.Command{
		Use:   "undelete -versions=1,2 PATH",
		Short: "Restore soft-deleted versions (KV v2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return kvVersionAction(cmd, args[0], "undelete", versions)
		},
	}
	cmd.Flags().StringVar(&versions, "versions", "", "Comma-separated versions to restore")
	return cmd
}

func newKVDestroyCmd() *cobra.Command {
	var versions string
	cmd := &cobra.Command{
		Use:   "destroy -versions=1,2 PATH",
		Short: "Permanently destroy versions (KV v2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return kvVersionAction(cmd, args[0], "destroy", versions)
		},
	}
	cmd.Flags().StringVar(&versions, "versions", "", "Comma-separated versions to destroy")
	return cmd
}

func kvVersionAction(cmd *cobra.Command, path, action, versions string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	m := resolveKVMount(c, path)
	if !m.v2 {
		return fmt.Errorf("%s is only supported on KV v2 mounts", action)
	}
	vs := parseVersions(versions)
	if len(vs) == 0 {
		return fmt.Errorf("-versions is required")
	}
	if _, err := c.Do(http.MethodPut, "/v1/"+m.subPath(action), map[string]any{"versions": vs}); err != nil {
		return err
	}
	success(cmd, "Success! Applied %s to version(s) %s at: %s\n", action, versions, path)
	return nil
}

// --- patch (read-modify-write, KV v2) ---

func newKVPatchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "patch PATH KEY=VALUE...",
		Short: "Update fields of the latest version without replacing it (KV v2)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			m := resolveKVMount(c, args[0])
			if !m.v2 {
				return fmt.Errorf("patch is only supported on KV v2 mounts")
			}
			patch, err := parseKV(args[1:])
			if err != nil {
				return err
			}
			cur, err := c.Do(http.MethodGet, "/v1/"+m.dataPath(), nil)
			if err != nil {
				return err
			}
			merged := map[string]any{}
			if d, ok := cur.Data["data"].(map[string]any); ok {
				for k, v := range d {
					merged[k] = v
				}
			}
			for k, v := range patch {
				merged[k] = v
			}
			resp, err := c.Do(http.MethodPut, "/v1/"+m.dataPath(), map[string]any{"data": merged})
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				fmt.Fprintf(w, "Success! Data patched at: %s\n", args[0])
				if v, ok := resp.Data["version"]; ok {
					fmt.Fprintf(w, "%-16s%v\n", "version", v)
				}
			})
		},
	}
}

// --- rollback (re-write an old version as the new latest, KV v2) ---

func newKVRollbackCmd() *cobra.Command {
	var version int
	cmd := &cobra.Command{
		Use:   "rollback -version=N PATH",
		Short: "Restore an older version as a new latest version (KV v2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if version <= 0 {
				return fmt.Errorf("-version is required")
			}
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			m := resolveKVMount(c, args[0])
			if !m.v2 {
				return fmt.Errorf("rollback is only supported on KV v2 mounts")
			}
			old, err := c.Do(http.MethodGet, "/v1/"+m.dataPath()+"?version="+strconv.Itoa(version), nil)
			if err != nil {
				return err
			}
			data, _ := old.Data["data"].(map[string]any)
			if data == nil {
				return fmt.Errorf("version %d has no data to roll back to", version)
			}
			resp, err := c.Do(http.MethodPut, "/v1/"+m.dataPath(), map[string]any{"data": data})
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				fmt.Fprintf(w, "Success! Rolled back %s to the contents of version %d\n", args[0], version)
				if v, ok := resp.Data["version"]; ok {
					fmt.Fprintf(w, "%-16s%v\n", "version", v)
				}
			})
		},
	}
	cmd.Flags().IntVar(&version, "version", 0, "Version to roll back to")
	return cmd
}

// --- metadata ---

func newKVMetadataCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Manage KV v2 key metadata",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "get PATH",
			Short: "Read a key's metadata and version history",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newClient(cmd)
				if err != nil {
					return err
				}
				m := resolveKVMount(c, args[0])
				resp, err := c.Do(http.MethodGet, "/v1/"+m.metadataPath(), nil)
				if err != nil {
					if resp != nil && resp.StatusCode == http.StatusNotFound {
						return noValue(args[0])
					}
					return err
				}
				return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
			},
		},
		newKVMetadataPutCmd(),
		&cobra.Command{
			Use:   "delete PATH",
			Short: "Delete a key and all its versions (KV v2)",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := newClient(cmd)
				if err != nil {
					return err
				}
				m := resolveKVMount(c, args[0])
				if _, err := c.Do(http.MethodDelete, "/v1/"+m.metadataPath(), nil); err != nil {
					return err
				}
				success(cmd, "Success! Metadata deleted (if it existed) at: %s\n", args[0])
				return nil
			},
		},
	)
	return cmd
}

func newKVMetadataPutCmd() *cobra.Command {
	var maxVersions int
	var casRequired bool
	cmd := &cobra.Command{
		Use:   "put [-max-versions=N] [-cas-required] PATH",
		Short: "Configure a key's metadata (KV v2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			m := resolveKVMount(c, args[0])
			body := map[string]any{}
			if cmd.Flags().Changed("max-versions") {
				body["max_versions"] = maxVersions
			}
			if cmd.Flags().Changed("cas-required") {
				body["cas_required"] = casRequired
			}
			if _, err := c.Do(http.MethodPut, "/v1/"+m.metadataPath(), body); err != nil {
				return err
			}
			success(cmd, "Success! Metadata written to: %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().IntVar(&maxVersions, "max-versions", 0, "Number of versions to keep")
	cmd.Flags().BoolVar(&casRequired, "cas-required", false, "Require check-and-set on writes")
	return cmd
}

// --- helpers ---

func parseVersions(s string) []int {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// kvV2GetTable renders a KV v2 data read: the version metadata then the data.
func kvV2GetTable(w io.Writer, data map[string]any) {
	if md, ok := data["metadata"].(map[string]any); ok {
		fmt.Fprintln(w, "===== Metadata =====")
		fmt.Fprintf(w, "%-16s%s\n", "Key", "Value")
		fmt.Fprintf(w, "%-16s%s\n", "---", "-----")
		for _, k := range []string{"version", "created_time", "deletion_time", "destroyed"} {
			if v, ok := md[k]; ok {
				fmt.Fprintf(w, "%-16s%v\n", k, v)
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "===== Data =====")
	inner, _ := data["data"].(map[string]any)
	if inner == nil {
		fmt.Fprintln(w, "(no data at this version)")
		return
	}
	kvTable(w, inner)
}
