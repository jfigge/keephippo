package command

import (
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

func newUnwrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unwrap [TOKEN]",
		Short: "Unwrap a response-wrapping token, returning the original data",
		Long: "Unwrap the data behind a response-wrapping token. With no argument, the\n" +
			"stored/authenticated token is treated as the wrapping token. Unwrapping\n" +
			"succeeds exactly once.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			var body map[string]any
			if len(args) == 1 {
				body = map[string]any{"token": args[0]}
			}
			resp, err := c.Do(http.MethodPost, "/v1/sys/wrapping/unwrap", body)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
		},
	}
}
