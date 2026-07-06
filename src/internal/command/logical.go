package command

import (
	"fmt"
	"io"
	"net/http"
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

func runRead(cmd *cobra.Command, path string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	resp, err := c.Do(http.MethodGet, "/v1/"+path, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return noValue(path)
		}
		return err
	}
	return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
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
	resp, err := c.Do(http.MethodPut, "/v1/"+path, data)
	if err != nil {
		return err
	}
	return emit(cmd, resp, func(w io.Writer) { fmt.Fprintf(w, "Success! Data written to: %s\n", path) })
}

func runList(cmd *cobra.Command, path string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	resp, err := c.Do("LIST", "/v1/"+path, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return noValue(path)
		}
		return err
	}
	return emit(cmd, resp, func(w io.Writer) { keysTable(w, resp.Data) })
}

func runDelete(cmd *cobra.Command, path string) error {
	c, err := newClient(cmd)
	if err != nil {
		return err
	}
	resp, err := c.Do(http.MethodDelete, "/v1/"+path, nil)
	if err != nil {
		return err
	}
	return emit(cmd, resp, func(w io.Writer) {
		fmt.Fprintf(w, "Success! Data deleted (if it existed) at: %s\n", path)
	})
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
