package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/barkleesanders/authy-exit/internal/migrate"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const Version = "0.1.0"

func Run(args []string, in io.Reader, out, stderr io.Writer) int {
	root := New(in, out, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		_ = json.NewEncoder(stderr).Encode(map[string]string{"error": err.Error()})
		return 1
	}
	return 0
}

func password(in io.Reader, errout io.Writer, stdin, noInput bool) ([]byte, error) {
	if stdin {
		b, err := io.ReadAll(io.LimitReader(in, 4097))
		if err != nil || len(b) > 4096 {
			return nil, errors.New("password stdin must contain at most 4096 bytes")
		}
		b = bytes.TrimSuffix(b, []byte("\n"))
		b = bytes.TrimSuffix(b, []byte("\r"))
		if len(b) == 0 {
			return nil, errors.New("empty backup password")
		}
		return b, nil
	}
	f, ok := in.(*os.File)
	if noInput || !ok || !term.IsTerminal(int(f.Fd())) {
		return nil, errors.New("use an interactive terminal or --password-stdin")
	}
	fmt.Fprint(errout, "Authy backup password (hidden): ")
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(errout)
	if err != nil || len(b) == 0 {
		return nil, errors.New("cannot read backup password")
	}
	return b, nil
}

func New(in io.Reader, out, errout io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "authy-exit", Short: "Recover and migrate your own Authy TOTP accounts locally", Version: Version, SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs}
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errout)
	root.CompletionOptions.DisableDefaultCmd = true
	var noInput bool
	root.PersistentFlags().BoolVar(&noInput, "no-input", false, "Fail instead of prompting")
	emit := func(v any) error { return json.NewEncoder(out).Encode(v) }
	var backup, plistPath, inventoryOut string
	inv := &cobra.Command{Use: "inventory", Short: "Extract only account metadata from your iPhone backup", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		var data migrate.Inventory
		var err error
		if (backup == "") == (plistPath == "") {
			return errors.New("provide exactly one of --backup or --plist")
		}
		if backup != "" {
			data, err = migrate.InventoryFromBackup(backup)
		} else {
			var b []byte
			b, err = migrate.Read(plistPath)
			if err == nil {
				data, err = migrate.InventoryFromPlist(b)
			}
		}
		if err != nil {
			return err
		}
		if err = migrate.WriteNew(inventoryOut, data); err != nil {
			return err
		}
		return emit(map[string]any{"accounts": len(data.Accounts), "written": true})
	}}
	inv.Flags().StringVar(&backup, "backup", "", "Finder/libimobiledevice backup directory containing Manifest.db")
	inv.Flags().StringVar(&plistPath, "plist", "", "Extracted Authy group preferences plist")
	inv.Flags().StringVar(&inventoryOut, "out", "", "New inventory JSON in a private directory")
	root.AddCommand(inv)
	var capturePath, inventoryPath, planOut string
	plan := &cobra.Command{Use: "plan", Short: "Prepare a metadata-only review plan; never guess a website", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		c, h, err := migrate.ReadCapture(capturePath)
		if err != nil {
			return err
		}
		var inventory migrate.Inventory
		var digest string
		if inventoryPath != "" {
			b, err := migrate.Read(inventoryPath)
			if err != nil {
				return err
			}
			if err = migrate.Decode(b, &inventory); err != nil {
				return err
			}
			digest = migrate.Hash(b)
		}
		p, err := migrate.BuildPlan(c, h, inventory)
		if err != nil {
			return err
		}
		p.InventorySHA256 = digest
		if err = migrate.WriteNew(planOut, p); err != nil {
			return err
		}
		return emit(migrate.Summary(p))
	}}
	plan.Flags().StringVar(&capturePath, "capture", "", "Encrypted token capture JSON")
	plan.Flags().StringVar(&inventoryPath, "inventory", "", "Optional iPhone metadata inventory JSON")
	plan.Flags().StringVar(&planOut, "out", "", "New review plan JSON in a private directory")
	root.AddCommand(plan)
	var exportCapture, reviewPath, exportOut string
	var stdin, dryRun bool
	export := &cobra.Command{Use: "export", Short: "Decrypt reviewed tokens and write a Bitwarden JSON import", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		c, h, err := migrate.ReadCapture(exportCapture)
		if err != nil {
			return err
		}
		p, err := migrate.ReadPlan(reviewPath, h, c)
		if err != nil {
			return err
		}
		pw, err := password(in, errout, stdin, noInput)
		if err != nil {
			return err
		}
		defer clear(pw)
		data, err := migrate.Export(c, p, pw)
		if err != nil {
			return err
		}
		if !dryRun {
			if err = migrate.WriteNew(exportOut, data); err != nil {
				return err
			}
		}
		return emit(map[string]any{"exported": len(data["items"].([]any)), "dry_run": dryRun, "written": !dryRun, "secrets_printed": false})
	}}
	export.Flags().StringVar(&exportCapture, "capture", "", "Encrypted token capture JSON")
	export.Flags().StringVar(&reviewPath, "plan", "", "Reviewed plan JSON")
	export.Flags().StringVar(&exportOut, "out", "", "New plaintext Bitwarden JSON; never stdout")
	export.Flags().BoolVar(&stdin, "password-stdin", false, "Read backup password from stdin, never a command-line argument")
	export.Flags().BoolVar(&dryRun, "dry-run", false, "Decrypt and validate all included tokens without writing an export")
	root.AddCommand(export)
	var verifyCapture, verifyPlan, verifyID string
	verify := &cobra.Command{Use: "verify", Short: "Compare a phone code with a locally generated TOTP without printing it", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		c, h, err := migrate.ReadCapture(verifyCapture)
		if err != nil {
			return err
		}
		p, err := migrate.ReadPlan(verifyPlan, h, c)
		if err != nil {
			return err
		}
		allowed := false
		for _, e := range p.Entries {
			if e.ID == verifyID && !e.Exclude {
				allowed = true
			}
		}
		if !allowed {
			return errors.New("ID is absent or excluded")
		}
		pw, err := password(in, errout, false, noInput)
		if err != nil {
			return err
		}
		defer clear(pw)
		var r migrate.Record
		for _, candidate := range c.Tokens {
			if migrate.ID(candidate) == verifyID {
				r = candidate
			}
		}
		if r == nil {
			return errors.New("no captured token for ID")
		}
		secret, err := migrate.Decrypt(r, pw)
		if err != nil {
			return err
		}
		if _, err = migrate.OTPURI(migrate.Entry{}, r, secret); err != nil {
			return err
		}
		f, ok := in.(*os.File)
		if !ok || !term.IsTerminal(int(f.Fd())) {
			return errors.New("verification requires a terminal")
		}
		fmt.Fprint(errout, "Current code shown on your iPhone (hidden): ")
		code, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(errout)
		if err != nil {
			return errors.New("cannot read phone code")
		}
		defer clear(code)
		digits, err := migrate.Integer(r, 6, "digits")
		if err != nil {
			return err
		}
		counter := time.Now().Unix() / 30
		for delta := int64(-1); delta <= 1; delta++ {
			expected, err := migrate.TOTP(secret, digits, uint64(counter+delta))
			if err != nil {
				return err
			}
			if string(code) == expected {
				return emit(map[string]any{"matches": true, "window_offset": delta})
			}
		}
		return errors.New("phone code did not match; check clock, account and source format")
	}}
	verify.Flags().StringVar(&verifyCapture, "capture", "", "Encrypted token capture JSON")
	verify.Flags().StringVar(&verifyPlan, "plan", "", "Reviewed plan JSON")
	verify.Flags().StringVar(&verifyID, "id", "", "Token ID from the private review plan")
	root.AddCommand(verify)
	root.AddCommand(captureCommand(in, out, errout))
	doctor := &cobra.Command{Use: "doctor", Short: "Check optional device, capture and vault tools without reading secrets", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		result := map[string]any{"version": Version, "core": "offline", "manual_steps": []string{"iPhone trust computer", "iPhone Wi-Fi proxy", "certificate install and full trust", "Authy sync", "review account mappings", "confirm codes"}}
		for _, name := range []string{"mitmdump", "idevice_id", "idevicebackup2", "bw"} {
			_, err := exec.LookPath(name)
			result[name] = err == nil
		}
		return emit(result)
	}}
	root.AddCommand(doctor)
	root.AddCommand(applyCommand(out))
	return root
}

func captureCommand(in io.Reader, out, errout io.Writer) *cobra.Command {
	var listen, phone, dir, addon string
	var port int
	c := &cobra.Command{Use: "capture", Short: "Run a foreground, device-scoped mitmproxy capture", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		for _, s := range []string{listen, phone} {
			ip := net.ParseIP(s)
			if ip == nil || !ip.IsPrivate() {
				return errors.New("--listen and --phone must be private LAN IP addresses")
			}
		}
		if port < 1024 || port > 65535 {
			return errors.New("port must be 1024..65535")
		}
		if dir == "" || addon == "" {
			return errors.New("--dir and --addon are required")
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return errors.New("invalid capture directory")
		}
		if err = os.MkdirAll(abs, 0700); err != nil {
			return errors.New("cannot create capture directory")
		}
		info, err := os.Stat(abs)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			return errors.New("capture directory must have mode 700")
		}
		addonAbs, err := filepath.Abs(addon)
		if err != nil {
			return errors.New("invalid addon path")
		}
		if _, err = os.Stat(addonAbs); err != nil {
			return errors.New("capture addon not found")
		}
		binary, err := exec.LookPath("mitmdump")
		if err != nil {
			return errors.New("mitmdump is missing; install mitmproxy first")
		}
		fmt.Fprintf(errout, "Set your iPhone Wi-Fi HTTP proxy to %s:%d, authentication off.\nInstall the certificate via http://mitm.it and enable full trust.\nOpen Authy and sync. Only the specified phone and Authy token route are saved.\nTurn the iPhone proxy OFF before stopping this process.\n", listen, port)
		cmd := exec.Command(binary, "--listen-host", listen, "--listen-port", fmt.Sprint(port), "--quiet", "--set", "confdir="+filepath.Join(abs, "mitmproxy"), "--set", "flow_detail=0", "--set", "termlog_verbosity=error", "--ignore-hosts", `^(?!api\.authy\.com(?::|$)|mitm\.it(?::|$)).*`, "-s", addonAbs)
		env := []string{}
		for _, s := range os.Environ() {
			if !strings.HasPrefix(s, "AUTHY_EXIT_") {
				env = append(env, s)
			}
		}
		cmd.Env = append(env, "AUTHY_EXIT_DIR="+abs, "AUTHY_EXIT_PHONE="+phone)
		cmd.Stdin = in
		cmd.Stdout = out
		cmd.Stderr = errout
		if err = cmd.Run(); err != nil {
			return errors.New("capture process stopped; turn off the iPhone proxy before disconnecting")
		}
		return nil
	}}
	c.Flags().StringVar(&listen, "listen", "", "Computer private LAN IP address")
	c.Flags().StringVar(&phone, "phone", "", "Your iPhone private LAN IP address")
	c.Flags().IntVar(&port, "port", 8088, "Proxy port")
	c.Flags().StringVar(&dir, "dir", "", "Private capture directory")
	c.Flags().StringVar(&addon, "addon", "", "Path to capture/mitm_authy.py from this project")
	return c
}
