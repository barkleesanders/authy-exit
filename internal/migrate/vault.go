package migrate

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

const SourceField = "authy-exit-source-id"

type Vault interface {
	Call(args []string, input any, output any) error
}
type BW struct{}

func (BW) Call(args []string, input any, output any) error {
	if os.Getenv("BW_SESSION") == "" {
		return errors.New("unlock the Bitwarden CLI and export BW_SESSION first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bw", args...)
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return errors.New("cannot encode vault update")
		}
		cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(b))
	}
	// Capture all child output in memory. Bitwarden returns complete secret-bearing
	// items, even for mutations; none of that output belongs in the terminal.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.New("Bitwarden command failed; check its login, unlock and server configuration")
	}
	if output != nil {
		if err := Decode(stdout.Bytes(), output); err != nil {
			return errors.New("unexpected Bitwarden response")
		}
	}
	return nil
}

type VaultOptions struct {
	User, Server, Receipt string
	Apply                 bool
}
type VaultResult struct {
	Created        int  `json:"created"`
	Attached       int  `json:"attached"`
	AlreadyPresent int  `json:"already_present"`
	Planned        int  `json:"planned"`
	DryRun         bool `json:"dry_run"`
}
type operation struct {
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Before Record `json:"before,omitempty"`
	Item   Record `json:"item"`
}

func sourceID(item Record) string {
	fields, _ := item["fields"].([]any)
	for _, raw := range fields {
		f, ok := raw.(map[string]any)
		if ok && Text(f, "name") == SourceField {
			return Text(f, "value")
		}
	}
	return ""
}
func login(item Record) Record { r, _ := item["login"].(map[string]any); return r }
func copyRecord(r Record) Record {
	b, _ := json.Marshal(r)
	var out Record
	_ = Decode(b, &out)
	return out
}
func sameItem(a, b Record) bool {
	a = copyRecord(a)
	b = copyRecord(b)
	delete(a, "revisionDate")
	delete(b, "revisionDate")
	return reflect.DeepEqual(a, b)
}

// ApplyVault attaches only to explicit target IDs. Labels never authorize a
// write. New entries carry a source marker so retries can detect prior creates.
func ApplyVault(v Vault, data Record, targets map[string]string, opt VaultOptions) (VaultResult, error) {
	result := VaultResult{DryRun: !opt.Apply}
	if opt.User == "" || opt.Server == "" {
		return result, errors.New("expected vault user and server are required")
	}
	var status Record
	if err := v.Call([]string{"status"}, nil, &status); err != nil {
		return result, err
	}
	if Text(status, "status") != "unlocked" || Text(status, "userEmail") != opt.User || strings.TrimRight(Text(status, "serverUrl"), "/") != strings.TrimRight(opt.Server, "/") {
		return result, errors.New("vault identity, server or unlock state does not match")
	}
	if err := v.Call([]string{"sync"}, nil, nil); err != nil {
		return result, err
	}
	var existing []Record
	if err := v.Call([]string{"list", "items"}, nil, &existing); err != nil {
		return result, err
	}
	byID := map[string]Record{}
	bySource := map[string][]Record{}
	for _, item := range existing {
		if Text(item, "deletedDate") != "" {
			continue
		}
		byID[Text(item, "id")] = item
		if id := sourceID(item); id != "" {
			bySource[id] = append(bySource[id], item)
		}
	}
	raw, ok := data["items"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 1000 || data["encrypted"] != false {
		return result, errors.New("expected an unencrypted authy-exit export containing 1..1000 items")
	}
	seen := map[string]bool{}
	usedTargets := map[string]bool{}
	ops := []operation{}
	for i, value := range raw {
		item, ok := value.(map[string]any)
		if !ok {
			return result, SlotError(i, "invalid item")
		}
		id := sourceID(item)
		l := login(item)
		if id == "" || seen[id] || l == nil || Text(l, "password") != "" || Text(l, "totp") == "" {
			return result, SlotError(i, "invalid or duplicate migration item")
		}
		seen[id] = true
		if Text(item, "type") != "1" {
			return result, SlotError(i, "expected a login item")
		}
		if err := validateURI(Text(l, "totp")); err != nil {
			return result, SlotError(i, err.Error())
		}
		target := targets[id]
		if target != "" && usedTargets[target] {
			return result, errors.New("multiple source tokens point to the same target; keep distinct seeds separate")
		}
		if target != "" {
			usedTargets[target] = true
		}
		matches := bySource[id]
		if len(matches) > 1 {
			return result, errors.New("multiple existing items have the same migration marker")
		}
		if len(matches) == 1 {
			if target != "" && Text(matches[0], "id") != target {
				return result, errors.New("source already exists in another vault item")
			}
			if Text(login(matches[0]), "totp") != Text(l, "totp") {
				return result, errors.New("existing source marker has a different seed")
			}
			result.AlreadyPresent++
			continue
		}
		if target == "" {
			fresh := copyRecord(item)
			delete(fresh, "id")
			delete(fresh, "folderId")
			ops = append(ops, operation{Source: id, Item: fresh})
			continue
		}
		before := byID[target]
		if before == nil || login(before) == nil {
			return result, errors.New("target is missing or is not a login")
		}
		if old := Text(login(before), "totp"); old != "" {
			if old == Text(l, "totp") {
				result.AlreadyPresent++
				continue
			}
			return result, errors.New("target already has a different TOTP; no overwrite was performed")
		}
		if sourceID(before) != "" {
			return result, errors.New("target belongs to a different migration source")
		}
		after := copyRecord(before)
		login(after)["totp"] = Text(l, "totp")
		fields, _ := after["fields"].([]any)
		after["fields"] = append(fields, map[string]any{"name": SourceField, "value": id, "type": 0})
		ops = append(ops, operation{Source: id, Target: target, Before: copyRecord(before), Item: copyRecord(after)})
	}
	for id := range targets {
		if !seen[id] {
			return result, errors.New("target mapping refers to a source absent from the export")
		}
	}
	result.Planned = len(ops)
	if !opt.Apply || len(ops) == 0 {
		return result, nil
	}
	// Save full preimages BEFORE the first write. This receipt contains secrets.
	if err := WriteNew(opt.Receipt, map[string]any{"version": 1, "created_at": time.Now().UTC().Format(time.RFC3339), "operations": ops}); err != nil {
		return result, err
	}
	var folders []Record
	if err := v.Call([]string{"list", "folders"}, nil, &folders); err != nil {
		return result, err
	}
	folder := ""
	for _, f := range folders {
		if Text(f, "name") == "Verification codes" {
			if folder != "" {
				return result, errors.New("multiple Verification codes folders; resolve before applying")
			}
			folder = Text(f, "id")
		}
	}
	if folder == "" {
		var f Record
		if err := v.Call([]string{"create", "folder"}, Record{"name": "Verification codes"}, &f); err != nil {
			return result, err
		}
		folder = Text(f, "id")
		if folder == "" {
			return result, errors.New("created folder has no ID")
		}
	}
	for _, op := range ops {
		op.Item["folderId"] = folder
		var written Record
		var err error
		if op.Target != "" {
			var current Record
			if err = v.Call([]string{"get", "item", op.Target}, nil, &current); err != nil {
				return result, err
			}
			if !sameItem(current, op.Before) {
				return result, errors.New("target changed since preflight; stopped before overwriting it")
			}
			err = v.Call([]string{"edit", "item", op.Target}, op.Item, &written)
		} else {
			err = v.Call([]string{"create", "item"}, op.Item, &written)
		}
		if err != nil {
			return result, fmt.Errorf("apply stopped after %d verified writes; rerun dry-run before retrying: %w", result.Created+result.Attached, err)
		}
		id := Text(written, "id")
		if id == "" {
			return result, errors.New("vault write returned no item ID")
		}
		var readback Record
		if err = v.Call([]string{"get", "item", id}, nil, &readback); err != nil {
			return result, err
		}
		if Text(login(readback), "totp") != Text(login(op.Item), "totp") || sourceID(readback) != op.Source || Text(readback, "folderId") != folder {
			return result, errors.New("vault readback verification failed; inspect the private receipt")
		}
		if op.Target != "" {
			// Compare every preserved field from the original item, including nested
			// passkeys, URIs, password history, custom fields and notes.
			for k, want := range op.Item {
				if k == "revisionDate" {
					continue
				}
				if !reflect.DeepEqual(want, readback[k]) {
					return result, errors.New("preservation verification failed; inspect the private receipt")
				}
			}
			result.Attached++
		} else {
			result.Created++
		}
	}
	return result, nil
}

func validateURI(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.User != nil {
		return errors.New("invalid TOTP URI")
	}
	q := u.Query()
	secret := q.Get("secret")
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	defer clear(seed)
	if err != nil || len(seed) < 10 || base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed) != secret {
		return errors.New("invalid TOTP secret")
	}
	if q.Get("algorithm") != "SHA1" || q.Get("period") != "30" || (q.Get("digits") != "6" && q.Get("digits") != "8") {
		return errors.New("unsupported TOTP parameters")
	}
	return nil
}
