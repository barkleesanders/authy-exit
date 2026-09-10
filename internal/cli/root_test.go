package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryCommandHelp(t *testing.T) {
	for _, command := range []string{"", "doctor", "inventory", "plan", "export", "verify", "capture", "apply"} {
		var out, stderr bytes.Buffer
		args := []string{"--help"}
		if command != "" {
			args = []string{command, "--help"}
		}
		if Run(args, strings.NewReader(""), &out, &stderr) != 0 || !strings.Contains(out.String(), "Usage:") {
			t.Fatalf("help failed for %s", command)
		}
	}
}
func TestNoPasswordArgsOrAccidentalPrompt(t *testing.T) {
	var out, stderr bytes.Buffer
	if Run([]string{"export", "--password", "DO_NOT_ECHO"}, strings.NewReader(""), &out, &stderr) == 0 {
		t.Fatal("accepted password flag")
	}
	if strings.Contains(stderr.String(), "DO_NOT_ECHO") {
		t.Fatal("echoed password argument")
	}
	if _, err := password(strings.NewReader("secret"), &stderr, false, true); err == nil {
		t.Fatal("prompted without terminal")
	}
}
func TestPlanCommandAndErrors(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	capture := filepath.Join(dir, "capture.json")
	_ = os.WriteFile(capture, []byte(`{"authenticator_tokens":[{"unique_id":"synthetic","name":"Private Label","account_name":"Generic Blue"}]}`), 0600)
	var out, stderr bytes.Buffer
	path := filepath.Join(dir, "plan.json")
	if Run([]string{"plan", "--capture", capture, "--out", path}, strings.NewReader(""), &out, &stderr) != 0 {
		t.Fatal(stderr.String())
	}
	if strings.Contains(out.String(), "Private Label") {
		t.Fatal("identity leaked to stdout")
	}
	out.Reset()
	stderr.Reset()
	if Run([]string{"export", "--capture", capture, "--plan", path, "--password-stdin", "--out", filepath.Join(dir, "export.json")}, strings.NewReader("secret"), &out, &stderr) == 0 {
		t.Fatal("unreviewed export accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "export.json")); !os.IsNotExist(err) {
		t.Fatal("failed export wrote output")
	}
}
