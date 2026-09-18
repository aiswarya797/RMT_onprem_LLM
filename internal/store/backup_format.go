package store

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"rmt.local/monitor/internal/config"
)

const (
	backupFormatVersion      = "1.0"
	backupManifestName       = "manifest.json"
	backupDatabaseName       = "monitor.sqlite3"
	BackupManifestLimitBytes = 1 << 20
	maxRecoveryKeyFileBytes  = 4 << 10
	maxBackupArchiveBytes    = LiveDataLimitBytes + 32<<20
	maxBackupFileEntries     = 4096
	maxBackupConfigBytes     = 1 << 20
	maxBackupKeyBytes        = 1 << 20
)

type BackupManifest struct {
	FormatVersion           string                `json:"format_version"`
	CreatedMS               int64                 `json:"created_ms"`
	RecoveryPointMS         int64                 `json:"recovery_point_ms"`
	DeploymentID            string                `json:"deployment_id"`
	DeploymentGeneration    string                `json:"deployment_generation"`
	SchemaVersion           int64                 `json:"schema_version"`
	RegistryRevision        string                `json:"registry_revision"`
	RecoveryRecipientSHA256 string                `json:"recovery_recipient_sha256"`
	KeyPackageSHA256        string                `json:"key_package_sha256"`
	Database                BackupManifestEntry   `json:"database"`
	Files                   []BackupManifestEntry `json:"files"`
	HighWater               BackupHighWaterMarks  `json:"high_water"`
}

type BackupManifestEntry struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type BackupHighWaterMarks struct {
	SourceFrameRowID  int64 `json:"source_frame_rowid"`
	SourceStatusRowID int64 `json:"source_status_rowid"`
	AuditRowID        int64 `json:"audit_rowid"`
}

type BackupVerification struct {
	Manifest       BackupManifest
	ManifestSHA256 string
}

// GenerateRecoveryKey creates one operator-held age X25519 identity. The
// private key is written only to the requested new 0600 file and is never
// returned, printed, placed in the archive or accepted through argv text.
func GenerateRecoveryKey(path string) (recipientSHA256 string, err error) {
	if err := validateNewAbsolutePath(path); err != nil {
		return "", err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generate recovery identity: %w", err)
	}
	if err := createExclusivePrivateFile(path, []byte(identity.String()+"\n")); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(identity.Recipient().String()))
	return hex.EncodeToString(sum[:]), nil
}

func loadRecoveryIdentity(path string) (*age.X25519Identity, string, error) {
	if !filepath.IsAbs(path) {
		return nil, "", errors.New("recovery key path must be absolute")
	}
	if err := config.ValidatePrivateFile(path); err != nil {
		return nil, "", fmt.Errorf("validate recovery key: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maxRecoveryKeyFileBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(encoded) == 0 || len(encoded) > maxRecoveryKeyFileBytes {
		return nil, "", errors.New("recovery key file exceeds bound")
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, "", errors.New("invalid recovery key file")
	}
	sum := sha256.Sum256([]byte(identity.Recipient().String()))
	return identity, hex.EncodeToString(sum[:]), nil
}

func writeEncryptedBackup(ctx context.Context, destination, databasePath string, inputs []backupInput, manifest BackupManifest, identity *age.X25519Identity) (string, string, error) {
	if err := validateNewAbsolutePath(destination); err != nil {
		return "", "", err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil || len(manifestJSON) == 0 || len(manifestJSON) > BackupManifestLimitBytes {
		return "", "", errors.New("backup manifest exceeds bound")
	}
	manifestSum := sha256.Sum256(manifestJSON)
	database, err := os.Open(databasePath)
	if err != nil {
		return "", "", err
	}
	defer database.Close()

	temporary, err := os.CreateTemp(filepath.Dir(destination), ".rmt-backup-*.tmp")
	if err != nil {
		return "", "", err
	}
	temporaryPath := temporary.Name()
	keepTemporary := false
	defer func() {
		if !keepTemporary {
			os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", "", err
	}
	encrypted, err := age.Encrypt(temporary, identity.Recipient())
	if err != nil {
		temporary.Close()
		return "", "", err
	}
	archive := tar.NewWriter(encrypted)
	writeEntry := func(name string, size int64, reader io.Reader) error {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, Typeflag: tar.TypeReg, ModTime: time.UnixMilli(manifest.CreatedMS)}); err != nil {
			return err
		}
		_, err := io.Copy(archive, &contextReader{ctx: ctx, reader: reader})
		return err
	}
	if err := writeEntry(backupManifestName, int64(len(manifestJSON)), strings.NewReader(string(manifestJSON))); err != nil {
		archive.Close()
		encrypted.Close()
		temporary.Close()
		return "", "", err
	}
	if err := writeEntry(backupDatabaseName, manifest.Database.Bytes, database); err != nil {
		archive.Close()
		encrypted.Close()
		temporary.Close()
		return "", "", err
	}
	for _, input := range inputs {
		if err := validateOwnedRegularFile(input.path, true); err != nil {
			archive.Close()
			encrypted.Close()
			temporary.Close()
			return "", "", err
		}
		file, err := os.Open(input.path)
		if err != nil {
			archive.Close()
			encrypted.Close()
			temporary.Close()
			return "", "", err
		}
		if err := archive.WriteHeader(&tar.Header{Name: input.entry.Name, Mode: 0o600, Size: input.entry.Bytes, Typeflag: tar.TypeReg, ModTime: time.UnixMilli(manifest.CreatedMS)}); err != nil {
			file.Close()
			archive.Close()
			encrypted.Close()
			temporary.Close()
			return "", "", err
		}
		hash := sha256.New()
		written, copyErr := io.Copy(archive, &contextReader{ctx: ctx, reader: io.TeeReader(io.LimitReader(file, input.entry.Bytes+1), hash)})
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != input.entry.Bytes || hex.EncodeToString(hash.Sum(nil)) != input.entry.SHA256 {
			archive.Close()
			encrypted.Close()
			temporary.Close()
			return "", "", errors.New("backup input changed during archive creation")
		}
	}
	if err := archive.Close(); err != nil {
		encrypted.Close()
		temporary.Close()
		return "", "", err
	}
	if err := encrypted.Close(); err != nil {
		temporary.Close()
		return "", "", fmt.Errorf("authenticate encrypted backup: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", "", err
	}
	if err := temporary.Close(); err != nil {
		return "", "", err
	}
	if info, err := os.Stat(temporaryPath); err != nil || info.Size() > maxBackupArchiveBytes {
		return "", "", errors.New("encrypted backup exceeds bound")
	}
	keepTemporary = true
	return hex.EncodeToString(manifestSum[:]), temporaryPath, nil
}

func decryptBackupToStaging(ctx context.Context, backupPath, keyPath, stagingDir, restoredDataDir string) (BackupVerification, string, error) {
	var empty BackupVerification
	if err := validateOwnedRegularFile(backupPath, false); err != nil {
		return empty, "", err
	}
	if err := validatePrivateDirectory(stagingDir); err != nil {
		return empty, "", err
	}
	identity, recipientHash, err := loadRecoveryIdentity(keyPath)
	if err != nil {
		return empty, "", err
	}
	backup, err := os.Open(backupPath)
	if err != nil {
		return empty, "", err
	}
	defer backup.Close()
	if info, err := backup.Stat(); err != nil || info.Size() <= 0 || info.Size() > maxBackupArchiveBytes {
		return empty, "", errors.New("encrypted backup size is outside bound")
	}
	plaintext, err := age.Decrypt(&contextReader{ctx: ctx, reader: backup}, identity)
	if err != nil {
		return empty, "", errors.New("backup authentication failed")
	}
	archive := tar.NewReader(plaintext)

	header, err := archive.Next()
	if err != nil || !validBackupHeader(header, backupManifestName, BackupManifestLimitBytes, false) {
		return empty, "", errors.New("invalid backup manifest entry")
	}
	manifestJSON, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: archive}, BackupManifestLimitBytes+1))
	if err != nil || int64(len(manifestJSON)) != header.Size {
		return empty, "", errors.New("incomplete backup manifest")
	}
	var manifest BackupManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestJSON)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || validateBackupManifest(manifest, recipientHash) != nil {
		return empty, "", errors.New("invalid backup manifest")
	}
	manifestSum := sha256.Sum256(manifestJSON)
	selectedAuxiliaryBytes := int64(0)
	if restoredDataDir != "" {
		for _, entry := range manifest.Files {
			if entry.Kind != "key_package" {
				if selectedAuxiliaryBytes > LiveDataLimitBytes-entry.Bytes {
					return empty, "", errors.New("backup restore selection exceeds bound")
				}
				selectedAuxiliaryBytes += entry.Bytes
			}
		}
	}
	stagingRequired := manifest.Database.Bytes
	if restoredDataDir != "" && sameFilesystem(stagingDir, restoredDataDir) {
		stagingRequired += selectedAuxiliaryBytes
	}
	if err := requireAvailableBytes(stagingDir, stagingRequired, EmergencyReserveBytes); err != nil {
		return empty, "", err
	}
	if restoredDataDir != "" && !sameFilesystem(stagingDir, restoredDataDir) {
		if err := requireAvailableBytes(restoredDataDir, selectedAuxiliaryBytes, EmergencyReserveBytes); err != nil {
			return empty, "", err
		}
	}

	header, err = archive.Next()
	if err != nil || !validBackupHeader(header, backupDatabaseName, LiveDataLimitBytes, false) || header.Size != manifest.Database.Bytes {
		return empty, "", errors.New("invalid backup database entry")
	}
	database, err := os.CreateTemp(stagingDir, ".rmt-verify-*.sqlite3")
	if err != nil {
		return empty, "", err
	}
	databasePath := database.Name()
	remove := true
	defer func() {
		if remove {
			os.Remove(databasePath)
		}
	}()
	if err := database.Chmod(0o600); err != nil {
		database.Close()
		return empty, "", err
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(database, hash), &contextReader{ctx: ctx, reader: io.LimitReader(archive, manifest.Database.Bytes+1)})
	if err != nil || written != manifest.Database.Bytes || hex.EncodeToString(hash.Sum(nil)) != manifest.Database.SHA256 {
		database.Close()
		return empty, "", errors.New("backup database hash mismatch")
	}
	if err := database.Sync(); err != nil {
		database.Close()
		return empty, "", err
	}
	if err := database.Close(); err != nil {
		return empty, "", err
	}
	for _, expected := range manifest.Files {
		header, err := archive.Next()
		if err != nil || !validBackupHeader(header, expected.Name, maximumBackupEntryBytes(expected.Kind), expected.Kind == "snapshot_blob") || header.Size != expected.Bytes {
			return empty, "", errors.New("invalid backup auxiliary entry")
		}
		hash := sha256.New()
		var destination io.Writer = hash
		var restored *os.File
		if restoredDataDir != "" && expected.Kind != "key_package" {
			restoredPath := filepath.Join(restoredDataDir, filepath.FromSlash(expected.Name))
			if !strings.HasPrefix(restoredPath, restoredDataDir+string(filepath.Separator)) {
				return empty, "", errors.New("backup restore path escaped destination")
			}
			if err := os.MkdirAll(filepath.Dir(restoredPath), 0o700); err != nil {
				return empty, "", err
			}
			restored, err = os.OpenFile(restoredPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return empty, "", err
			}
			destination = io.MultiWriter(restored, hash)
		}
		written, err := io.Copy(destination, &contextReader{ctx: ctx, reader: io.LimitReader(archive, expected.Bytes+1)})
		if restored != nil {
			if syncErr := restored.Sync(); err == nil {
				err = syncErr
			}
			if closeErr := restored.Close(); err == nil {
				err = closeErr
			}
			if syncErr := syncDirectory(filepath.Dir(restored.Name())); err == nil {
				err = syncErr
			}
		}
		if err != nil || written != expected.Bytes || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return empty, "", errors.New("backup auxiliary hash mismatch")
		}
	}
	if next, err := archive.Next(); err != io.EOF || next != nil {
		return empty, "", errors.New("unexpected backup archive entry")
	}
	if trailing, err := io.Copy(io.Discard, &contextReader{ctx: ctx, reader: plaintext}); err != nil || trailing != 0 {
		return empty, "", errors.New("backup authentication or trailing-data check failed")
	}
	if restoredDataDir != "" {
		if err := syncDirectory(restoredDataDir); err != nil {
			return empty, "", err
		}
	}
	verification := BackupVerification{Manifest: manifest, ManifestSHA256: hex.EncodeToString(manifestSum[:])}
	remove = false
	return verification, databasePath, nil
}

func validateBackupManifest(manifest BackupManifest, recipientHash string) error {
	if manifest.FormatVersion != backupFormatVersion || manifest.CreatedMS < 0 || manifest.RecoveryPointMS < 0 || manifest.RecoveryPointMS > manifest.CreatedMS || !validUUIDText(manifest.DeploymentID) || !validUUIDText(manifest.DeploymentGeneration) || manifest.SchemaVersion < 1 || manifest.RegistryRevision == "" || manifest.RecoveryRecipientSHA256 != recipientHash || !sha256HexPattern.MatchString(manifest.KeyPackageSHA256) || manifest.Database.Name != backupDatabaseName || manifest.Database.Kind != "database" || manifest.Database.Bytes <= 0 || manifest.Database.Bytes > LiveDataLimitBytes || !sha256HexPattern.MatchString(manifest.Database.SHA256) || len(manifest.Files) < 5 || len(manifest.Files) > maxBackupFileEntries {
		return errors.New("invalid backup manifest fields")
	}
	keyHash := sha256.New()
	keyCount := 0
	present := make(map[string]bool, len(manifest.Files))
	previous := ""
	var total int64
	for _, entry := range manifest.Files {
		if entry.Name <= previous || !validManifestEntry(entry) || total > LiveDataLimitBytes-entry.Bytes {
			return errors.New("invalid backup file manifest")
		}
		previous = entry.Name
		present[entry.Name] = true
		total += entry.Bytes
		if entry.Kind == "key_package" {
			fmt.Fprintf(keyHash, "%s\x00%d\x00%s\n", entry.Name, entry.Bytes, entry.SHA256)
			keyCount++
		}
	}
	for _, required := range []string{"config/hub.json", "config/collector.json", "keys/session.key", "keys/ca.key", "keys/ca.pem"} {
		if !present[required] {
			return errors.New("backup manifest is missing a required file")
		}
	}
	if present["keys/hub.key"] != present["keys/hub.pem"] || keyCount < 3 || hex.EncodeToString(keyHash.Sum(nil)) != manifest.KeyPackageSHA256 || manifest.Database.Bytes > LiveDataLimitBytes-total {
		return errors.New("invalid backup key package or total size")
	}
	if manifest.HighWater.SourceFrameRowID < 0 || manifest.HighWater.SourceStatusRowID < 0 || manifest.HighWater.AuditRowID < 0 {
		return errors.New("invalid backup high-water marks")
	}
	return nil
}

func validManifestEntry(entry BackupManifestEntry) bool {
	if entry.Bytes < 0 || entry.Bytes > maximumBackupEntryBytes(entry.Kind) || (entry.Bytes == 0 && entry.Kind != "snapshot_blob") || !sha256HexPattern.MatchString(entry.SHA256) {
		return false
	}
	switch entry.Kind {
	case "config":
		return entry.Name == "config/hub.json" || entry.Name == "config/collector.json"
	case "key_package":
		return entry.Name == "keys/session.key" || entry.Name == "keys/ca.key" || entry.Name == "keys/ca.pem" || entry.Name == "keys/hub.key" || entry.Name == "keys/hub.pem"
	case "snapshot_blob":
		return strings.HasPrefix(entry.Name, "snapshots/") && validBackupRelativePath(strings.TrimPrefix(entry.Name, "snapshots/"))
	case "notification_secret":
		ref := strings.TrimPrefix(entry.Name, "notification-secrets/")
		return strings.HasPrefix(entry.Name, "notification-secrets/") && ((ref == "key" && entry.Bytes == 32) || (sha256HexPattern.MatchString(ref) && entry.Bytes >= 29))
	case "attachment_blob":
		return strings.HasPrefix(entry.Name, "attachments/") && validBackupRelativePath(strings.TrimPrefix(entry.Name, "attachments/"))
	default:
		return false
	}
}

func maximumBackupEntryBytes(kind string) int64 {
	switch kind {
	case "config":
		return maxBackupConfigBytes
	case "key_package":
		return maxBackupKeyBytes
	case "snapshot_blob":
		return 100 << 20
	case "notification_secret":
		return 4125
	case "attachment_blob":
		return 10 << 20
	default:
		return 0
	}
}

func validBackupHeader(header *tar.Header, name string, maximum int64, allowEmpty bool) bool {
	return header != nil && header.Name == name && filepath.Clean(header.Name) == header.Name && !filepath.IsAbs(header.Name) && header.Typeflag == tar.TypeReg && header.Linkname == "" && header.Size >= 0 && (allowEmpty || header.Size > 0) && header.Size <= maximum && header.Mode&0o077 == 0 && header.Mode&0o600 == 0o600
}

func validateNewAbsolutePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("output path must be clean and absolute")
	}
	if err := validatePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("refuse to overwrite existing path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validatePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("private directory path must be absolute")
	}
	if err := config.RejectSymlinkTree(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("private directory must be current-user owned with mode 0700")
	}
	return nil
}

func validateOwnedRegularFile(path string, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("file path must be clean and absolute")
	}
	if err := config.RejectSymlinkTree(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || int(stat.Uid) != os.Getuid() {
		return errors.New("file must be a current-user-owned regular file")
	}
	if private && info.Mode().Perm() != 0o600 {
		return errors.New("private file mode must be 0600")
	}
	return nil
}

func createExclusivePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		file.Close()
		if !keep {
			os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	keep = true
	return nil
}

func createExclusivePrivateDirectory(path string) error {
	if err := validateNewAbsolutePath(path); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func publishExclusive(source, destination string) error {
	if err := validateNewAbsolutePath(destination); err != nil {
		return err
	}
	if err := os.Link(source, destination); err != nil {
		return fmt.Errorf("publish without overwrite: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		os.Remove(destination)
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sameFilesystem(first, second string) bool {
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	firstStat, firstOK := firstInfo.Sys().(*syscall.Stat_t)
	secondStat, secondOK := secondInfo.Sys().(*syscall.Stat_t)
	return firstErr == nil && secondErr == nil && firstOK && secondOK && firstStat.Dev == secondStat.Dev
}

func requireAvailableBytes(path string, contentBytes, reserveBytes int64) error {
	if contentBytes < 0 || reserveBytes < 0 || contentBytes > int64(^uint64(0)>>1)-reserveBytes {
		return errors.New("backup staging space requirement exceeds bound")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("measure backup staging space: %w", err)
	}
	if stat.Bavail < 0 || stat.Bsize <= 0 || uint64(stat.Bavail) > ^uint64(0)/uint64(stat.Bsize) {
		return errors.New("invalid backup staging capacity")
	}
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
	required := uint64(contentBytes + reserveBytes)
	if available < required {
		return errors.New("insufficient space for verified backup staging and reserve")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(buffer)
	}
}
