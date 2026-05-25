package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/cert"
	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/control"
	"anixops-sd-wan/internal/store"
)

func main() {
	defaults := config.Default()
	addr := flag.String("addr", defaults.Control.ListenAddr, "control plane listen address")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file for HTTPS management API")
	tlsKey := flag.String("tls-key", "", "TLS private key file for HTTPS management API")
	requireClientCert := flag.Bool("require-client-cert", false, "require and verify client certificates signed by the control CA")
	caCert := flag.String("ca-cert", "", "control CA certificate PEM file")
	caKey := flag.String("ca-key", "", "control CA EC private key PEM file")
	caBackupFile := flag.String("ca-backup-file", "", "write a verified backup of --ca-cert/--ca-key and exit")
	caRestoreFile := flag.String("ca-restore-file", "", "restore a verified backup into --ca-cert/--ca-key and exit")
	storeFile := flag.String("store-file", "", "JSON file for durable control plane domain state")
	storeBackupFile := flag.String("store-backup-file", "", "write a verified backup of --store-file and exit")
	storeRestoreFile := flag.String("store-restore-file", "", "restore a verified backup into --store-file and exit")
	sessionFile := flag.String("session-file", "", "JSON file for durable control plane bearer sessions")
	passwordUsersFile := flag.String("password-users-file", "", "JSON file containing hashed password login users")
	oidcConfigFile := flag.String("oidc-config-file", "", "JSON file containing static OIDC ID token verifier config")
	configSigningKeyFile := flag.String("config-signing-key-file", "", "Ed25519 private key PEM file for durable config signing")
	crlPublishDir := flag.String("crl-publish-dir", "", "directory for publishing tenant CRL PEM files and JSON manifests")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	info := buildinfo.Current("anix-control")
	if *showVersion {
		fmt.Printf("%s %s %s %s\n", info.Name, info.Version, info.Commit, info.Date)
		return
	}
	storeMaintenance := *storeBackupFile != "" || *storeRestoreFile != ""
	caMaintenance := *caBackupFile != "" || *caRestoreFile != ""
	if storeMaintenance && caMaintenance {
		fmt.Fprintln(os.Stderr, "only one backup or restore operation can be run at a time")
		os.Exit(2)
	}
	if storeMaintenance {
		if *storeBackupFile != "" && *storeRestoreFile != "" {
			fmt.Fprintln(os.Stderr, "--store-backup-file and --store-restore-file cannot be used together")
			os.Exit(2)
		}
		if *storeFile == "" {
			fmt.Fprintln(os.Stderr, "--store-file is required for store backup or restore")
			os.Exit(2)
		}
		if *storeRestoreFile != "" {
			backup, err := restoreStoreBackup(*storeFile, *storeRestoreFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "restore store backup: %v\n", err)
				os.Exit(1)
			}
			encodeJSON(backup)
			return
		}
		backup, err := writeStoreBackup(*storeFile, *storeBackupFile, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "write store backup: %v\n", err)
			os.Exit(1)
		}
		encodeJSON(backup)
		return
	}
	if caMaintenance {
		if *caBackupFile != "" && *caRestoreFile != "" {
			fmt.Fprintln(os.Stderr, "--ca-backup-file and --ca-restore-file cannot be used together")
			os.Exit(2)
		}
		if *caCert == "" || *caKey == "" {
			fmt.Fprintln(os.Stderr, "--ca-cert and --ca-key are required for CA backup or restore")
			os.Exit(2)
		}
		if *caRestoreFile != "" {
			backup, err := restoreCABackup(*caCert, *caKey, *caRestoreFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "restore CA backup: %v\n", err)
				os.Exit(1)
			}
			encodeJSON(backup)
			return
		}
		backup, err := writeCABackup(*caCert, *caKey, *caBackupFile, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "write CA backup: %v\n", err)
			os.Exit(1)
		}
		encodeJSON(backup)
		return
	}

	authority := loadAuthority(*caCert, *caKey)
	repository := loadRepository(*storeFile)
	sessions := loadSessions(*sessionFile)
	passwords := loadPasswordAuthenticator(*passwordUsersFile)
	oidc := loadOIDCAuthenticator(*oidcConfigFile)
	configSigner, err := loadConfigSigner(*configSigningKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config signing key: %v\n", err)
		os.Exit(1)
	}
	var persistSigner control.ConfigSignerPersistFunc
	if *configSigningKeyFile != "" {
		persistSigner = func(signer *config.ConfigSigner) error {
			return persistConfigSigner(*configSigningKeyFile, signer)
		}
	}
	controlServer := control.NewServerWithDependenciesAndSignerPersist(info, repository, authority, sessions, configSigner, persistSigner)
	if passwords != nil {
		controlServer.SetPasswordAuthenticator(passwords)
	}
	if oidc != nil {
		controlServer.SetOIDCAuthenticator(oidc)
	}
	if *crlPublishDir != "" {
		publisher, err := cert.NewFileRevocationListPublisher(*crlPublishDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load crl publisher: %v\n", err)
			os.Exit(1)
		}
		controlServer.SetRevocationListPublisher(publisher)
	}
	handler := controlServer.Handler()
	server := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			fmt.Fprintln(os.Stderr, "both --tls-cert and --tls-key are required for HTTPS")
			os.Exit(2)
		}
		tlsConfig, err := controlServer.ManagementTLSConfig(*requireClientCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "control TLS config error: %v\n", err)
			os.Exit(1)
		}
		server.TLSConfig = tlsConfig
	} else if *requireClientCert {
		fmt.Fprintln(os.Stderr, "--require-client-cert requires --tls-cert and --tls-key")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "anix-control listening on %s\n", *addr)
	if *tlsCert != "" {
		err = server.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "control server error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "anix-control stopped")
}

func loadAuthority(certPath, keyPath string) *cert.Authority {
	if certPath == "" && keyPath == "" {
		return nil
	}
	if certPath == "" || keyPath == "" {
		fmt.Fprintln(os.Stderr, "both --ca-cert and --ca-key are required for durable control CA state")
		os.Exit(2)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read control CA certificate: %v\n", err)
		os.Exit(1)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read control CA key: %v\n", err)
		os.Exit(1)
	}
	authority, err := cert.NewAuthorityFromPEM(certPEM, keyPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load control CA: %v\n", err)
		os.Exit(1)
	}
	return authority
}

func loadRepository(path string) store.Repository {
	if path == "" {
		return nil
	}
	repository, err := store.NewFileRepository(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load control store: %v\n", err)
		os.Exit(1)
	}
	return repository
}

func writeStoreBackup(storePath, backupPath string, createdAt time.Time) (store.Backup, error) {
	repository, err := store.NewFileRepository(storePath)
	if err != nil {
		return store.Backup{}, err
	}
	return repository.Backup(backupPath, createdAt)
}

func restoreStoreBackup(storePath, backupPath string) (store.Backup, error) {
	return store.RestoreBackupFile(storePath, backupPath)
}

func writeCABackup(certPath, keyPath, backupPath string, createdAt time.Time) (cert.AuthorityBackup, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return cert.AuthorityBackup{}, fmt.Errorf("read authority certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return cert.AuthorityBackup{}, fmt.Errorf("read authority private key: %w", err)
	}
	authority, err := cert.NewAuthorityFromPEM(certPEM, keyPEM)
	if err != nil {
		return cert.AuthorityBackup{}, err
	}
	return authority.Backup(backupPath, createdAt)
}

func restoreCABackup(certPath, keyPath, backupPath string) (cert.AuthorityBackup, error) {
	return cert.RestoreAuthorityBackupFile(certPath, keyPath, backupPath)
}

func encodeJSON(value interface{}) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		os.Exit(1)
	}
}

func loadSessions(path string) auth.SessionManager {
	if path == "" {
		return nil
	}
	sessions, err := auth.NewFileSessionStore(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load control sessions: %v\n", err)
		os.Exit(1)
	}
	return sessions
}

func loadPasswordAuthenticator(path string) *auth.PasswordAuthenticator {
	if path == "" {
		return nil
	}
	authenticator, err := auth.LoadPasswordAuthenticator(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load password users: %v\n", err)
		os.Exit(1)
	}
	return authenticator
}

func loadOIDCAuthenticator(path string) *auth.OIDCAuthenticator {
	if path == "" {
		return nil
	}
	authenticator, err := auth.LoadOIDCAuthenticator(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load oidc config: %v\n", err)
		os.Exit(1)
	}
	return authenticator
}

func loadConfigSigner(path string) (*config.ConfigSigner, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := validatePrivateControlFile(path, "config signing key file"); err != nil {
			return nil, err
		}
		return config.NewConfigSignerFromPEM(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read config signing key: %w", err)
	}
	signer, err := config.NewConfigSigner()
	if err != nil {
		return nil, err
	}
	if err := persistConfigSigner(path, signer); err != nil {
		return nil, err
	}
	return signer, nil
}

func validatePrivateControlFile(path, name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must be a file", name)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s must not be group/world accessible; got mode %o", name, mode)
	}
	return nil
}

func persistConfigSigner(path string, signer *config.ConfigSigner) error {
	pemBytes, err := signer.PrivateKeyPEM()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config signing key directory: %w", err)
	}
	if dir != "." {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("chmod config signing key directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".config-signing-key-*.tmp")
	if err != nil {
		return fmt.Errorf("create config signing key temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod config signing key temp file: %w", err)
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config signing key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config signing key temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config signing key: %w", err)
	}
	return nil
}
