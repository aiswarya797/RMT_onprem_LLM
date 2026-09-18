package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type BackupAuxiliaryPaths struct {
	HubConfigPath          string
	CollectorConfigPath    string
	SessionSecretPath      string
	CAKeyPath              string
	CACertificatePath      string
	HubKeyPath             string
	HubCertificatePath     string
	SnapshotBlobRoot       string
	AttachmentBlobRoot     string
	NotificationSecretRoot string
}

type backupInput struct {
	path  string
	entry BackupManifestEntry
}

func prepareBackupInputs(ctx context.Context, snapshotPath string, paths BackupAuxiliaryPaths) ([]backupInput, string, int64, error) {
	fixed := []struct {
		name, kind, path string
		maximum          int64
	}{
		{"config/hub.json", "config", paths.HubConfigPath, maxBackupConfigBytes},
		{"config/collector.json", "config", paths.CollectorConfigPath, maxBackupConfigBytes},
		{"keys/session.key", "key_package", paths.SessionSecretPath, maxBackupKeyBytes},
		{"keys/ca.key", "key_package", paths.CAKeyPath, maxBackupKeyBytes},
		{"keys/ca.pem", "key_package", paths.CACertificatePath, maxBackupKeyBytes},
	}
	if (paths.HubKeyPath == "") != (paths.HubCertificatePath == "") {
		return nil, "", 0, errors.New("hub key and certificate must be included together")
	}
	if paths.HubKeyPath != "" {
		fixed = append(fixed,
			struct {
				name, kind, path string
				maximum          int64
			}{"keys/hub.key", "key_package", paths.HubKeyPath, maxBackupKeyBytes},
			struct {
				name, kind, path string
				maximum          int64
			}{"keys/hub.pem", "key_package", paths.HubCertificatePath, maxBackupKeyBytes},
		)
	}
	inputs := make([]backupInput, 0, len(fixed)+32)
	var auxiliaryBytes int64
	for _, value := range fixed {
		if value.path == "" {
			return nil, "", 0, fmt.Errorf("required backup input %s is missing", value.name)
		}
		if err := validateOwnedRegularFile(value.path, true); err != nil {
			return nil, "", 0, fmt.Errorf("validate %s: %w", value.name, err)
		}
		size, digest, err := hashFile(value.path, value.maximum)
		if err != nil {
			return nil, "", 0, err
		}
		inputs = append(inputs, backupInput{path: value.path, entry: BackupManifestEntry{Name: value.name, Kind: value.kind, Bytes: size, SHA256: digest}})
		auxiliaryBytes += size
	}
	if err := validatePrivateDirectory(paths.SnapshotBlobRoot); err != nil {
		return nil, "", 0, fmt.Errorf("validate snapshot blob root: %w", err)
	}
	database, err := openSnapshotDatabase(snapshotPath, true)
	if err != nil {
		return nil, "", 0, err
	}
	defer database.Close()
	secretRows, err := database.QueryContext(ctx, `SELECT secret_ref FROM destinations WHERE secret_ref IS NOT NULL AND secret_ref!=''
		UNION SELECT destination_secret_ref FROM outbox WHERE state='leased' AND destination_secret_ref IS NOT NULL AND destination_secret_ref!=''
		ORDER BY 1 LIMIT 4097`)
	if err != nil {
		return nil, "", 0, err
	}
	var refs []string
	for secretRows.Next() {
		var ref string
		if err := secretRows.Scan(&ref); err != nil {
			secretRows.Close()
			return nil, "", 0, err
		}
		if !sha256HexPattern.MatchString(ref) {
			secretRows.Close()
			return nil, "", 0, errors.New("invalid notification secret reference")
		}
		refs = append(refs, ref)
	}
	if err := secretRows.Err(); err != nil {
		secretRows.Close()
		return nil, "", 0, err
	}
	secretRows.Close()
	if len(refs) > 4096 {
		return nil, "", 0, errors.New("notification secret count exceeds bound")
	}
	if len(refs) > 0 {
		if err := validatePrivateDirectory(paths.NotificationSecretRoot); err != nil {
			return nil, "", 0, errors.New("notification secrets unavailable for backup")
		}
		for _, ref := range append([]string{"key"}, refs...) {
			path := filepath.Join(paths.NotificationSecretRoot, ref)
			if err := validateOwnedRegularFile(path, true); err != nil {
				return nil, "", 0, err
			}
			size, digest, err := hashFile(path, 4125)
			if err != nil || (ref == "key" && size != 32) || (ref != "key" && size < 29) {
				return nil, "", 0, errors.New("notification secret envelope invalid")
			}
			inputs = append(inputs, backupInput{path: path, entry: BackupManifestEntry{Name: "notification-secrets/" + ref, Kind: "notification_secret", Bytes: size, SHA256: digest}})
			auxiliaryBytes += size
		}
	}

	rows, err := database.QueryContext(ctx, `SELECT relative_blob_path,size_bytes,payload_hash FROM snapshots ORDER BY relative_blob_path`)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()
	seen := make(map[string]bool)
	for rows.Next() {
		var relative, expectedHash string
		var expectedSize int64
		if err := rows.Scan(&relative, &expectedSize, &expectedHash); err != nil {
			return nil, "", 0, err
		}
		if !validBackupRelativePath(relative) || seen[relative] || !sha256HexPattern.MatchString(expectedHash) || expectedSize < 0 || expectedSize > 100<<20 {
			return nil, "", 0, errors.New("invalid or duplicate snapshot blob manifest")
		}
		seen[relative] = true
		path := filepath.Join(paths.SnapshotBlobRoot, filepath.FromSlash(relative))
		if err := validateOwnedRegularFile(path, true); err != nil {
			return nil, "", 0, fmt.Errorf("validate snapshot blob %s: %w", relative, err)
		}
		size, digest, err := hashFileBounded(path, 100<<20, true)
		if err != nil || size != expectedSize || digest != expectedHash {
			return nil, "", 0, fmt.Errorf("snapshot blob %s does not match database manifest", relative)
		}
		inputs = append(inputs, backupInput{path: path, entry: BackupManifestEntry{Name: "snapshots/" + relative, Kind: "snapshot_blob", Bytes: size, SHA256: digest}})
		if auxiliaryBytes > LiveDataLimitBytes-size {
			return nil, "", 0, errors.New("backup auxiliary input exceeds live-data bound")
		}
		auxiliaryBytes += size
		if len(inputs) > maxBackupFileEntries {
			return nil, "", 0, errors.New("backup file entry count exceeds bound")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", 0, err
	}
	attachmentRows, err := database.QueryContext(ctx, `SELECT relative_blob_path,size_bytes,sha256 FROM attachments ORDER BY relative_blob_path`)
	if err != nil {
		return nil, "", 0, err
	}
	defer attachmentRows.Close()
	attachmentRootValidated := false
	seenAttachments := make(map[string]bool)
	for attachmentRows.Next() {
		var relative, expectedHash string
		var expectedSize int64
		if err := attachmentRows.Scan(&relative, &expectedSize, &expectedHash); err != nil {
			return nil, "", 0, err
		}
		if !validBackupRelativePath(relative) || seenAttachments[relative] || !sha256HexPattern.MatchString(expectedHash) || expectedSize <= 0 || expectedSize > 10<<20 {
			return nil, "", 0, errors.New("invalid or duplicate attachment blob manifest")
		}
		seenAttachments[relative] = true
		if !attachmentRootValidated {
			if err := validatePrivateDirectory(paths.AttachmentBlobRoot); err != nil {
				return nil, "", 0, fmt.Errorf("validate attachment blob root: %w", err)
			}
			attachmentRootValidated = true
		}
		path := filepath.Join(paths.AttachmentBlobRoot, filepath.FromSlash(relative))
		if err := validateOwnedRegularFile(path, true); err != nil {
			return nil, "", 0, fmt.Errorf("validate attachment blob %s: %w", relative, err)
		}
		size, digest, err := hashFile(path, 10<<20)
		if err != nil || size != expectedSize || digest != expectedHash {
			return nil, "", 0, fmt.Errorf("attachment blob %s does not match database manifest", relative)
		}
		inputs = append(inputs, backupInput{path: path, entry: BackupManifestEntry{Name: "attachments/" + relative, Kind: "attachment_blob", Bytes: size, SHA256: digest}})
		if auxiliaryBytes > LiveDataLimitBytes-size {
			return nil, "", 0, errors.New("backup auxiliary input exceeds live-data bound")
		}
		auxiliaryBytes += size
		if len(inputs) > maxBackupFileEntries {
			return nil, "", 0, errors.New("backup file entry count exceeds bound")
		}
	}
	if err := attachmentRows.Err(); err != nil {
		return nil, "", 0, err
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].entry.Name < inputs[j].entry.Name })
	keyHash := sha256.New()
	keyCount := 0
	for _, input := range inputs {
		if input.entry.Kind == "key_package" {
			fmt.Fprintf(keyHash, "%s\x00%d\x00%s\n", input.entry.Name, input.entry.Bytes, input.entry.SHA256)
			keyCount++
		}
	}
	if keyCount < 3 {
		return nil, "", 0, errors.New("backup key package is incomplete")
	}
	return inputs, hex.EncodeToString(keyHash.Sum(nil)), auxiliaryBytes, nil
}

func validBackupRelativePath(value string) bool {
	if value == "" || len(value) > 240 || strings.ContainsRune(value, '\x00') || filepath.IsAbs(value) || filepath.Clean(value) != value || filepath.ToSlash(filepath.Clean(value)) != value {
		return false
	}
	return value != "." && value != ".." && !strings.HasPrefix(value, "../")
}
