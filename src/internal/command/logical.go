package command

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// Generic path commands: read / write / delete / list. The kv subcommands
// (see kv.go) reuse the same helpers.

func newReadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "read PATH",
		Short: "Read data from the given path",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runRead(cmd, args[0]) },
	}
}

func newWriteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "write PATH [KEY=VALUE...]",
		Short: "Write data to the given path",
		Args:  cobra.MinimumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runWrite(cmd, args[0], args[1:]) },
	}
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete PATH",
		Short: "Delete data at the given path",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runDelete(cmd, args[0]) },
	}
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list PATH",
		Short: "List keys at the given path",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runList(cmd, args[0]) },
	}
}

func runWrite(cmd *cobra.Command, path string, kvArgs []string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	data, err := parseKV(kvArgs)
	if err != nil {
		return err
	}
	if err := c.Write(path, data); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Success! Data written to: %s\n", path)
	return nil
}

func runRead(cmd *cobra.Command, path string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	sec, err := c.Read(path)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no value found at %s", path)
	}
	printData(cmd, sec.Data)
	return nil
}

func runList(cmd *cobra.Command, path string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	sec, err := c.List(path)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no value found at %s", path)
	}
	printKeys(cmd, sec.Data)
	return nil
}

func runDelete(cmd *cobra.Command, path string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	if err := c.Delete(path); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Success! Data deleted (if it existed) at: %s\n", path)
	return nil
}

func parseKV(args []string) (map[string]any, error) {
	data := make(map[string]any, len(args))
	for _, a := range args {
		i := strings.IndexByte(a, '=')
		if i < 0 {
			return nil, fmt.Errorf("invalid key=value pair %q", a)
		}
		data[a[:i]] = a[i+1:]
	}
	return data, nil
}

func printData(cmd *cobra.Command, data map[string]any) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "%-20s%s\n", "Key", "Value")
	fmt.Fprintf(w, "%-20s%s\n", "---", "-----")
	for _, k := range sortedKeys(data) {
		fmt.Fprintf(w, "%-20s%v\n", k, data[k])
	}
}

func printKeys(cmd *cobra.Command, data map[string]any) {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Keys")
	fmt.Fprintln(w, "----")
	if raw, ok := data["keys"].([]any); ok {
		for _, k := range raw {
			fmt.Fprintf(w, "%v\n", k)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
