package cli

import (
	"encoding/json"
	"github.com/barkleesanders/authy-exit/internal/migrate"
	"github.com/spf13/cobra"
	"io"
)

func applyCommand(out io.Writer) *cobra.Command {
	var file, mapping, receipt, user, server string
	var yes bool
	c := &cobra.Command{Use: "apply", Short: "Preview or apply reviewed codes to an explicitly identified Bitwarden vault", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		b, err := migrate.Read(file)
		if err != nil {
			return err
		}
		var data migrate.Record
		if err = migrate.Decode(b, &data); err != nil {
			return err
		}
		targets := map[string]string{}
		if mapping != "" {
			b, err = migrate.Read(mapping)
			if err != nil {
				return err
			}
			if err = migrate.Decode(b, &targets); err != nil {
				return err
			}
		}
		result, err := migrate.ApplyVault(migrate.BW{}, data, targets, migrate.VaultOptions{User: user, Server: server, Receipt: receipt, Apply: yes})
		if encodeErr := json.NewEncoder(out).Encode(result); encodeErr != nil {
			return encodeErr
		}
		return err
	}}
	c.Flags().StringVar(&file, "file", "", "Plaintext JSON produced by authy-exit export")
	c.Flags().StringVar(&mapping, "targets", "", "Optional JSON mapping source token IDs to existing vault item IDs")
	c.Flags().StringVar(&receipt, "receipt", "", "New private rollback receipt file (contains secrets; required with --yes)")
	c.Flags().StringVar(&user, "expected-user", "", "Exact email of the intended Bitwarden account")
	c.Flags().StringVar(&server, "expected-server", "", "Exact URL returned by bw status")
	c.Flags().BoolVar(&yes, "yes", false, "Apply changes after preflight; otherwise preview only")
	return c
}
