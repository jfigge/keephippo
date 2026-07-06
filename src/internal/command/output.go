package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/api"
)

// outputFormat returns the effective --format ("table" or "json").
func outputFormat(cmd *cobra.Command) string {
	f, _ := cmd.Flags().GetString("format")
	if f == "" {
		return "table"
	}
	return f
}

// emit renders resp per --format: json prints the raw response envelope,
// table calls tableFn. It is the single output path for data-returning commands.
func emit(cmd *cobra.Command, resp *api.Response, tableFn func(w io.Writer)) error {
	if outputFormat(cmd) == "json" {
		return printJSON(cmd.OutOrStdout(), resp.Raw)
	}
	if resp.WrapInfo != nil {
		wrapInfoTable(cmd.OutOrStdout(), resp.WrapInfo)
		return nil
	}
	tableFn(cmd.OutOrStdout())
	return nil
}

func wrapInfoTable(w io.Writer, wi *api.WrapInfo) {
	fmt.Fprintf(w, "%-22s%s\n", "Key", "Value")
	fmt.Fprintf(w, "%-22s%s\n", "---", "-----")
	fmt.Fprintf(w, "%-22s%s\n", "wrapping_token:", wi.Token)
	fmt.Fprintf(w, "%-22s%d\n", "wrapping_token_ttl:", wi.TTL)
	fmt.Fprintf(w, "%-22s%s\n", "wrapping_token_creation_time:", wi.CreationTime)
	fmt.Fprintf(w, "%-22s%s\n", "wrapping_token_creation_path:", wi.CreationPath)
}

// success prints a human-readable message in table mode; json mode is silent
// (matching Vault, whose write/enable/revoke produce no JSON body).
func success(cmd *cobra.Command, format string, args ...any) {
	if outputFormat(cmd) == "json" {
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), format, args...)
}

func printJSON(w io.Writer, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		fmt.Fprintln(w, string(raw))
		return nil
	}
	fmt.Fprintln(w, buf.String())
	return nil
}

// exitCoder lets an error request a specific process exit code.
type exitCoder interface{ ExitCode() int }

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }
func (e *exitError) ExitCode() int { return e.code }

// noValue is the Vault-style "no data" error (exit code 2).
func noValue(path string) error {
	return &exitError{code: 2, msg: "No value found at " + path}
}

// --- table renderers ---

func kvTable(w io.Writer, data map[string]any) {
	fmt.Fprintf(w, "%-20s%s\n", "Key", "Value")
	fmt.Fprintf(w, "%-20s%s\n", "---", "-----")
	for _, k := range sortedKeys(data) {
		fmt.Fprintf(w, "%-20s%v\n", k, data[k])
	}
}

func keysTable(w io.Writer, data map[string]any) {
	fmt.Fprintln(w, "Keys")
	fmt.Fprintln(w, "----")
	for _, k := range anyToStrings(data["keys"]) {
		fmt.Fprintln(w, k)
	}
}

func pathTypeTable(w io.Writer, header string, data map[string]any) {
	fmt.Fprintf(w, "%-16s%s\n", header, "Type")
	fmt.Fprintf(w, "%-16s%s\n", "----", "----")
	for _, p := range sortedKeys(data) {
		m, _ := data[p].(map[string]any)
		fmt.Fprintf(w, "%-16s%v\n", p, m["type"])
	}
}

func authTable(w io.Writer, resp *api.Response) {
	a := resp.Auth
	if a == nil {
		return
	}
	fmt.Fprintf(w, "%-20s%s\n", "Key", "Value")
	fmt.Fprintf(w, "%-20s%s\n", "---", "-----")
	fmt.Fprintf(w, "%-20s%s\n", "token", a.ClientToken)
	fmt.Fprintf(w, "%-20s%s\n", "token_accessor", a.Accessor)
	fmt.Fprintf(w, "%-20s%d\n", "token_duration", a.LeaseDuration)
	fmt.Fprintf(w, "%-20s%v\n", "token_renewable", a.Renewable)
	fmt.Fprintf(w, "%-20s%v\n", "token_policies", a.Policies)
}

// printSealStatus renders a seal-status response (json passthrough or table).
func printSealStatus(cmd *cobra.Command, resp *api.Response) error {
	return emit(cmd, resp, func(w io.Writer) {
		var s struct {
			Type        string `json:"type"`
			Initialized bool   `json:"initialized"`
			Sealed      bool   `json:"sealed"`
			T           int    `json:"t"`
			N           int    `json:"n"`
			Progress    int    `json:"progress"`
			Version     string `json:"version"`
			StorageType string `json:"storage_type"`
		}
		_ = json.Unmarshal(resp.Raw, &s)
		fmt.Fprintf(w, "%-16s%s\n", "Key", "Value")
		fmt.Fprintf(w, "%-16s%s\n", "---", "-----")
		fmt.Fprintf(w, "%-16s%s\n", "Seal Type", s.Type)
		fmt.Fprintf(w, "%-16s%t\n", "Initialized", s.Initialized)
		fmt.Fprintf(w, "%-16s%t\n", "Sealed", s.Sealed)
		fmt.Fprintf(w, "%-16s%d\n", "Total Shares", s.N)
		fmt.Fprintf(w, "%-16s%d\n", "Threshold", s.T)
		if s.Sealed && s.Initialized {
			fmt.Fprintf(w, "%-16s%d/%d\n", "Unseal Progress", s.Progress, s.T)
		}
		fmt.Fprintf(w, "%-16s%s\n", "Version", s.Version)
		fmt.Fprintf(w, "%-16s%s\n", "Storage Type", s.StorageType)
	})
}

// respSealed reports whether a seal-status response indicates a sealed server.
func respSealed(resp *api.Response) bool {
	var s struct {
		Sealed bool `json:"sealed"`
	}
	_ = json.Unmarshal(resp.Raw, &s)
	return s.Sealed
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func anyToStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	}
	return nil
}
