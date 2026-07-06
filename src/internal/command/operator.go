package command

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newOperatorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Perform operator-level commands (init, unseal)",
	}
	cmd.AddCommand(newOperatorInitCmd(), newOperatorUnsealCmd())
	return cmd
}

func newOperatorInitCmd() *cobra.Command {
	var shares, threshold int
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a keephippo server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			res, err := c.Init(shares, threshold)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			for i, k := range res.Keys {
				fmt.Fprintf(w, "Unseal Key %d: %s\n", i+1, k)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "Initial Root Token: %s\n", res.RootToken)
			fmt.Fprintln(w)
			fmt.Fprintf(w, "keephippo initialized with %d key share(s) and a threshold of %d.\n", len(res.Keys), threshold)
			fmt.Fprintf(w, "Distribute the key shares securely. %d of them are required to unseal.\n", threshold)
			return nil
		},
	}
	cmd.Flags().IntVar(&shares, "key-shares", 5, "Number of key shares to split the root key into")
	cmd.Flags().IntVar(&threshold, "key-threshold", 3, "Number of key shares required to unseal")
	return cmd
}

func newOperatorUnsealCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unseal [KEY]",
		Short: "Submit an unseal key share",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}

			var key string
			if len(args) == 1 {
				key = strings.TrimSpace(args[0])
			} else {
				fmt.Fprint(cmd.OutOrStdout(), "Unseal Key: ")
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				key = strings.TrimSpace(line)
			}
			if key == "" {
				return fmt.Errorf("an unseal key is required")
			}

			st, err := c.Unseal(key)
			if err != nil {
				return err
			}
			printSealStatus(cmd, st)
			return nil
		},
	}
}
