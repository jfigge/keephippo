package command

import "github.com/spf13/cobra"

func newKVCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kv",
		Short: "Interact with the KV secrets engine",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "put PATH KEY=VALUE...",
			Short: "Write a secret",
			Args:  cobra.MinimumNArgs(2),
			RunE:  func(cmd *cobra.Command, args []string) error { return runWrite(cmd, args[0], args[1:]) },
		},
		&cobra.Command{
			Use:   "get PATH",
			Short: "Read a secret",
			Args:  cobra.ExactArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return runRead(cmd, args[0]) },
		},
		&cobra.Command{
			Use:   "list PATH",
			Short: "List secrets",
			Args:  cobra.ExactArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return runList(cmd, args[0]) },
		},
		&cobra.Command{
			Use:   "delete PATH",
			Short: "Delete a secret",
			Args:  cobra.ExactArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return runDelete(cmd, args[0]) },
		},
	)
	return cmd
}
