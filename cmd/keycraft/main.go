package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unsafe"
)

const (
	vaultVersion      = 1
	defaultIterations = 210_000
	keyLength         = 32
	saltLength        = 16
	defaultVaultFile  = "vault.json"
)

var errEntryNotFound = errors.New("entry not found")

var (
	kernel32DLL        = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode = kernel32DLL.NewProc("SetConsoleMode")
)

type kdfConfig struct {
	Name       string `json:"name"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
}

type vaultEnvelope struct {
	Version    int       `json:"version"`
	KDF        kdfConfig `json:"kdf"`
	Cipher     string    `json:"cipher"`
	CreatedAt  string    `json:"created_at"`
	UpdatedAt  string    `json:"updated_at"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

type vaultData struct {
	Entries []entry `json:"entries"`
}

type entry struct {
	ID        string   `json:"id"`
	Service   string   `json:"service"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	URL       string   `json:"url,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

type optionalString struct {
	value string
	set   bool
}

func (o *optionalString) String() string {
	return o.value
}

func (o *optionalString) Set(v string) error {
	o.value = v
	o.set = true
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]
	if command == "help" || command == "-h" || command == "--help" {
		printUsage()
		return
	}

	var err error
	switch command {
	case "init":
		err = runInit(os.Args[2:])
	case "add":
		err = runAdd(os.Args[2:])
	case "list":
		err = runList(os.Args[2:])
	case "get":
		err = runGet(os.Args[2:])
	case "update":
		err = runUpdate(os.Args[2:])
	case "delete":
		err = runDelete(os.Args[2:])
	case "generate":
		err = runGenerate(os.Args[2:])
	case "change-master":
		err = runChangeMaster(os.Args[2:])
	default:
		printUsage()
		err = fmt.Errorf("unknown command %q", command)
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var vaultPath string
	fs.StringVar(&vaultPath, "vault", "", "Vault file path (default: ~/.keycraft/vault.json)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	path, err := resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	master, err := promptNewMasterPassword()
	if err != nil {
		return err
	}

	if err := createVault(path, master); err != nil {
		return err
	}

	fmt.Printf("Initialized vault at %s\n", path)
	return nil
}

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var vaultPath, service, username, accountPassword, url, notes, tagsRaw string
	fs.StringVar(&vaultPath, "vault", "", "Vault file path")
	fs.StringVar(&service, "service", "", "Service name (required)")
	fs.StringVar(&username, "username", "", "Username/login (required)")
	fs.StringVar(&accountPassword, "password", "", "Password for the account")
	fs.StringVar(&url, "url", "", "URL for the account")
	fs.StringVar(&notes, "notes", "", "Notes")
	fs.StringVar(&tagsRaw, "tags", "", "Comma-separated tags")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	path, err := resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}

	if strings.TrimSpace(service) == "" {
		service, err = readLine("Service: ", false)
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(username) == "" {
		username, err = readLine("Username: ", false)
		if err != nil {
			return err
		}
	}
	if accountPassword == "" {
		accountPassword, err = readSecret("Account password: ", false)
		if err != nil {
			return err
		}
	}

	master, err := promptMasterPassword()
	if err != nil {
		return err
	}

	env, data, err := loadVault(path, master)
	if err != nil {
		return err
	}

	service = strings.TrimSpace(service)
	username = strings.TrimSpace(username)
	if hasDuplicate(data.Entries, service, username, "") {
		return fmt.Errorf("entry already exists for service=%q username=%q", service, username)
	}

	now := nowUTC()
	e := entry{
		ID:        generateEntryID(),
		Service:   service,
		Username:  username,
		Password:  accountPassword,
		URL:       strings.TrimSpace(url),
		Notes:     notes,
		Tags:      parseTags(tagsRaw),
		CreatedAt: now,
		UpdatedAt: now,
	}

	data.Entries = append(data.Entries, e)
	if err := saveVault(path, env, data, master); err != nil {
		return err
	}

	fmt.Printf("Added entry %s (%s / %s)\n", e.ID, e.Service, e.Username)
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var vaultPath, search string
	fs.StringVar(&vaultPath, "vault", "", "Vault file path")
	fs.StringVar(&search, "search", "", "Case-insensitive search filter")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	path, err := resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}
	master, err := promptMasterPassword()
	if err != nil {
		return err
	}
	_, data, err := loadVault(path, master)
	if err != nil {
		return err
	}

	var entries []entry
	for _, e := range data.Entries {
		if matchesSearch(e, search) {
			entries = append(entries, e)
		}
	}

	if len(entries) == 0 {
		fmt.Println("No entries found.")
		return nil
	}

	sort.Slice(entries, func(i, j int) bool {
		if strings.EqualFold(entries[i].Service, entries[j].Service) {
			return strings.ToLower(entries[i].Username) < strings.ToLower(entries[j].Username)
		}
		return strings.ToLower(entries[i].Service) < strings.ToLower(entries[j].Service)
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSERVICE\tUSERNAME\tUPDATED")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.ID, e.Service, e.Username, e.UpdatedAt)
	}
	return w.Flush()
}

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var vaultPath, id, service, username string
	var showPassword bool
	fs.StringVar(&vaultPath, "vault", "", "Vault file path")
	fs.StringVar(&id, "id", "", "Entry ID")
	fs.StringVar(&service, "service", "", "Service name")
	fs.StringVar(&username, "username", "", "Username/login")
	fs.BoolVar(&showPassword, "show-password", false, "Show plaintext password")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if strings.TrimSpace(id) == "" && strings.TrimSpace(service) == "" {
		return errors.New("provide --id or --service")
	}

	path, err := resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}
	master, err := promptMasterPassword()
	if err != nil {
		return err
	}
	_, data, err := loadVault(path, master)
	if err != nil {
		return err
	}

	idx, err := findEntryIndex(data.Entries, id, service, username)
	if err != nil {
		return err
	}
	e := data.Entries[idx]

	password := "<hidden>"
	if showPassword {
		password = e.Password
	}

	fmt.Printf("ID:        %s\n", e.ID)
	fmt.Printf("Service:   %s\n", e.Service)
	fmt.Printf("Username:  %s\n", e.Username)
	fmt.Printf("Password:  %s\n", password)
	fmt.Printf("URL:       %s\n", e.URL)
	fmt.Printf("Tags:      %s\n", strings.Join(e.Tags, ","))
	fmt.Printf("Notes:     %s\n", e.Notes)
	fmt.Printf("Created:   %s\n", e.CreatedAt)
	fmt.Printf("Updated:   %s\n", e.UpdatedAt)
	if !showPassword {
		fmt.Println("Tip: re-run with --show-password to reveal it.")
	}
	return nil
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var vaultPath, id string
	var serviceOpt, usernameOpt, passwordOpt, urlOpt, notesOpt, tagsOpt optionalString
	fs.StringVar(&vaultPath, "vault", "", "Vault file path")
	fs.StringVar(&id, "id", "", "Entry ID (required)")
	fs.Var(&serviceOpt, "service", "New service name")
	fs.Var(&usernameOpt, "username", "New username/login")
	fs.Var(&passwordOpt, "password", "New password ('-' to prompt securely)")
	fs.Var(&urlOpt, "url", "New URL")
	fs.Var(&notesOpt, "notes", "New notes")
	fs.Var(&tagsOpt, "tags", "New comma-separated tags")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("--id is required")
	}
	if !serviceOpt.set && !usernameOpt.set && !passwordOpt.set && !urlOpt.set && !notesOpt.set && !tagsOpt.set {
		return errors.New("nothing to update; pass at least one field")
	}

	if passwordOpt.set && passwordOpt.value == "-" {
		p, err := readSecret("New account password: ", false)
		if err != nil {
			return err
		}
		passwordOpt.value = p
	}

	path, err := resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}
	master, err := promptMasterPassword()
	if err != nil {
		return err
	}
	env, data, err := loadVault(path, master)
	if err != nil {
		return err
	}

	idx, err := findEntryIndex(data.Entries, id, "", "")
	if err != nil {
		return err
	}
	e := data.Entries[idx]

	if serviceOpt.set {
		e.Service = strings.TrimSpace(serviceOpt.value)
		if e.Service == "" {
			return errors.New("--service cannot be empty")
		}
	}
	if usernameOpt.set {
		e.Username = strings.TrimSpace(usernameOpt.value)
		if e.Username == "" {
			return errors.New("--username cannot be empty")
		}
	}
	if passwordOpt.set {
		e.Password = passwordOpt.value
		if e.Password == "" {
			return errors.New("--password cannot be empty")
		}
	}
	if urlOpt.set {
		e.URL = strings.TrimSpace(urlOpt.value)
	}
	if notesOpt.set {
		e.Notes = notesOpt.value
	}
	if tagsOpt.set {
		e.Tags = parseTags(tagsOpt.value)
	}

	if hasDuplicate(data.Entries, e.Service, e.Username, e.ID) {
		return fmt.Errorf("another entry already exists for service=%q username=%q", e.Service, e.Username)
	}

	e.UpdatedAt = nowUTC()
	data.Entries[idx] = e

	if err := saveVault(path, env, data, master); err != nil {
		return err
	}

	fmt.Printf("Updated entry %s\n", e.ID)
	return nil
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var vaultPath, id string
	var force bool
	fs.StringVar(&vaultPath, "vault", "", "Vault file path")
	fs.StringVar(&id, "id", "", "Entry ID (required)")
	fs.BoolVar(&force, "force", false, "Delete without confirmation")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("--id is required")
	}

	path, err := resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}
	master, err := promptMasterPassword()
	if err != nil {
		return err
	}
	env, data, err := loadVault(path, master)
	if err != nil {
		return err
	}

	idx, err := findEntryIndex(data.Entries, id, "", "")
	if err != nil {
		return err
	}
	e := data.Entries[idx]

	if !force {
		confirm, err := readLine(fmt.Sprintf("Delete %q (%q)? Type 'yes' to confirm: ", e.Service, e.Username), true)
		if err != nil {
			return err
		}
		if strings.ToLower(strings.TrimSpace(confirm)) != "yes" {
			return errors.New("aborted")
		}
	}

	data.Entries = append(data.Entries[:idx], data.Entries[idx+1:]...)
	if err := saveVault(path, env, data, master); err != nil {
		return err
	}

	fmt.Printf("Deleted entry %s\n", id)
	return nil
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var length int
	var noSymbols, noAmbiguous bool
	fs.IntVar(&length, "length", 24, "Password length")
	fs.BoolVar(&noSymbols, "no-symbols", false, "Exclude symbols")
	fs.BoolVar(&noAmbiguous, "no-ambiguous", false, "Exclude ambiguous characters (O0Il1)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	pw, err := generatePassword(length, !noSymbols, noAmbiguous)
	if err != nil {
		return err
	}

	fmt.Println(pw)
	return nil
}

func runChangeMaster(args []string) error {
	fs := flag.NewFlagSet("change-master", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var vaultPath string
	fs.StringVar(&vaultPath, "vault", "", "Vault file path")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	path, err := resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}

	currentMaster, err := promptMasterPassword()
	if err != nil {
		return err
	}
	env, data, err := loadVault(path, currentMaster)
	if err != nil {
		return err
	}

	newMaster, err := promptNewMasterPassword()
	if err != nil {
		return err
	}

	salt, err := randomBytes(saltLength)
	if err != nil {
		return err
	}
	env.KDF.Salt = base64.StdEncoding.EncodeToString(salt)
	env.KDF.Iterations = defaultIterations
	env.KDF.Name = "pbkdf2-sha256"

	if err := saveVault(path, env, data, newMaster); err != nil {
		return err
	}

	fmt.Println("Master password updated.")
	return nil
}

func createVault(path, master string) error {
	salt, err := randomBytes(saltLength)
	if err != nil {
		return err
	}
	now := nowUTC()
	env := &vaultEnvelope{
		Version:   vaultVersion,
		Cipher:    "aes-256-gcm",
		CreatedAt: now,
		UpdatedAt: now,
		KDF: kdfConfig{
			Name:       "pbkdf2-sha256",
			Iterations: defaultIterations,
			Salt:       base64.StdEncoding.EncodeToString(salt),
		},
	}
	data := &vaultData{Entries: []entry{}}
	return saveVault(path, env, data, master)
}

func loadVault(path, master string) (*vaultEnvelope, *vaultData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("vault not found at %s (run `keycraft init` first)", path)
		}
		return nil, nil, err
	}

	var env vaultEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("vault metadata is invalid: %w", err)
	}

	if err := validateEnvelope(&env); err != nil {
		return nil, nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(env.KDF.Salt)
	if err != nil {
		return nil, nil, fmt.Errorf("vault salt is invalid: %w", err)
	}
	key, err := deriveKey(master, salt, env.KDF.Iterations)
	if err != nil {
		return nil, nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("vault nonce is invalid: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("vault ciphertext is invalid: %w", err)
	}

	plaintext, err := decrypt(key, nonce, ciphertext)
	if err != nil {
		return nil, nil, errors.New("failed to decrypt vault (wrong master password or corrupted file)")
	}

	var data vaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, nil, fmt.Errorf("vault payload is invalid: %w", err)
	}
	if data.Entries == nil {
		data.Entries = []entry{}
	}

	return &env, &data, nil
}

func saveVault(path string, env *vaultEnvelope, data *vaultData, master string) error {
	if env == nil || data == nil {
		return errors.New("internal error: nil vault")
	}
	if err := validateEnvelope(env); err != nil {
		return err
	}

	salt, err := base64.StdEncoding.DecodeString(env.KDF.Salt)
	if err != nil {
		return fmt.Errorf("vault salt is invalid: %w", err)
	}
	key, err := deriveKey(master, salt, env.KDF.Iterations)
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to serialize vault: %w", err)
	}

	nonce, ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		return err
	}

	env.Nonce = base64.StdEncoding.EncodeToString(nonce)
	env.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	if env.CreatedAt == "" {
		env.CreatedAt = nowUTC()
	}
	env.UpdatedAt = nowUTC()

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode vault file: %w", err)
	}
	out = append(out, '\n')

	if err := writeFileAtomic(path, out); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
	}
	return nil
}

func validateEnvelope(env *vaultEnvelope) error {
	if env.Version != vaultVersion {
		return fmt.Errorf("unsupported vault version: %d", env.Version)
	}
	if env.Cipher != "aes-256-gcm" {
		return fmt.Errorf("unsupported cipher: %s", env.Cipher)
	}
	if env.KDF.Name != "pbkdf2-sha256" {
		return fmt.Errorf("unsupported KDF: %s", env.KDF.Name)
	}
	if env.KDF.Iterations < 100_000 {
		return fmt.Errorf("KDF iterations too low: %d", env.KDF.Iterations)
	}
	if strings.TrimSpace(env.KDF.Salt) == "" {
		return errors.New("vault salt is missing")
	}
	if env.Nonce != "" && env.Ciphertext == "" {
		return errors.New("vault ciphertext is missing")
	}
	return nil
}

func deriveKey(master string, salt []byte, iterations int) ([]byte, error) {
	if strings.TrimSpace(master) == "" {
		return nil, errors.New("master password cannot be empty")
	}
	key, err := pbkdf2.Key(sha256.New, master, salt, iterations, keyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}
	return key, nil
}

func encrypt(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize AEAD: %w", err)
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AEAD: %w", err)
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func findEntryIndex(entries []entry, id, service, username string) (int, error) {
	id = strings.TrimSpace(id)
	service = strings.TrimSpace(service)
	username = strings.TrimSpace(username)

	if id != "" {
		for i := range entries {
			if strings.EqualFold(entries[i].ID, id) {
				return i, nil
			}
		}
		return -1, errEntryNotFound
	}
	if service == "" {
		return -1, errors.New("service is required when id is not provided")
	}

	var matches []int
	for i := range entries {
		if !strings.EqualFold(entries[i].Service, service) {
			continue
		}
		if username != "" && !strings.EqualFold(entries[i].Username, username) {
			continue
		}
		matches = append(matches, i)
	}

	switch len(matches) {
	case 0:
		return -1, errEntryNotFound
	case 1:
		return matches[0], nil
	default:
		if username == "" {
			return -1, errors.New("multiple entries matched service; include --username or --id")
		}
		return matches[0], nil
	}
}

func hasDuplicate(entries []entry, service, username, excludeID string) bool {
	service = strings.TrimSpace(service)
	username = strings.TrimSpace(username)
	for _, e := range entries {
		if excludeID != "" && strings.EqualFold(e.ID, excludeID) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(e.Service), service) &&
			strings.EqualFold(strings.TrimSpace(e.Username), username) {
			return true
		}
	}
	return false
}

func parseTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		key := strings.ToLower(tag)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, tag)
	}
	return out
}

func matchesSearch(e entry, search string) bool {
	search = strings.ToLower(strings.TrimSpace(search))
	if search == "" {
		return true
	}

	candidates := []string{e.ID, e.Service, e.Username, e.URL, e.Notes}
	candidates = append(candidates, e.Tags...)
	for _, c := range candidates {
		if strings.Contains(strings.ToLower(c), search) {
			return true
		}
	}
	return false
}

func resolveVaultPath(pathFlag string) (string, error) {
	if strings.TrimSpace(pathFlag) != "" {
		return filepath.Abs(pathFlag)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}
	return filepath.Join(home, ".keycraft", defaultVaultFile), nil
}

func promptMasterPassword() (string, error) {
	return readSecret("Master password: ", false)
}

func promptNewMasterPassword() (string, error) {
	first, err := readSecret("New master password: ", false)
	if err != nil {
		return "", err
	}
	second, err := readSecret("Confirm master password: ", false)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("master passwords do not match")
	}
	if err := validateMasterPasswordStrength(first); err != nil {
		return "", err
	}
	return first, nil
}

func validateMasterPasswordStrength(master string) error {
	if len(master) < 12 {
		return errors.New("master password must be at least 12 characters")
	}
	var hasLower, hasUpper, hasDigit bool
	for _, r := range master {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasLower || !hasUpper || !hasDigit {
		return errors.New("master password must include upper, lower, and numeric characters")
	}
	return nil
}

func readLine(prompt string, allowEmpty bool) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	return readLineAfterPrompt(allowEmpty)
}

func readLineAfterPrompt(allowEmpty bool) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimRight(line, "\r\n")
	if !allowEmpty && strings.TrimSpace(value) == "" {
		return "", errors.New("value cannot be empty")
	}
	return value, nil
}

func readSecret(prompt string, allowEmpty bool) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	var value string
	var err error

	if runtime.GOOS == "windows" && stdinIsConsole() {
		value, err = readSecretWindows()
	} else {
		value, err = readLineAfterPrompt(allowEmpty)
	}

	if err != nil {
		return "", err
	}
	if !allowEmpty && strings.TrimSpace(value) == "" {
		return "", errors.New("value cannot be empty")
	}
	return value, nil
}

func stdinIsConsole() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func readSecretWindows() (string, error) {
	handle, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	if err != nil {
		return readLineAfterPrompt(false)
	}

	var mode uint32
	if err := syscall.GetConsoleMode(handle, &mode); err != nil {
		return readLineAfterPrompt(false)
	}

	const enableEchoInput = 0x0004
	if err := setConsoleMode(handle, mode&^enableEchoInput); err != nil {
		return readLineAfterPrompt(false)
	}
	defer setConsoleMode(handle, mode)

	value, err := readLineAfterPrompt(true)
	fmt.Fprintln(os.Stderr)
	return value, err
}

func setConsoleMode(handle syscall.Handle, mode uint32) error {
	r1, _, callErr := procSetConsoleMode.Call(uintptr(handle), uintptr(mode))
	if r1 != 0 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return fmt.Errorf("SetConsoleMode failed for handle %v", unsafe.Pointer(uintptr(handle)))
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if runtime.GOOS == "windows" {
		_ = os.Remove(path)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to replace vault file: %w", err)
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}
	return out, nil
}

func generateEntryID() string {
	b, err := randomBytes(16)
	if err != nil {
		// This should be effectively unreachable; panic keeps ID generation strict.
		panic(err)
	}
	return hex.EncodeToString(b)
}

func generatePassword(length int, includeSymbols bool, noAmbiguous bool) (string, error) {
	if length < 8 {
		return "", errors.New("length must be at least 8")
	}

	lower := "abcdefghijklmnopqrstuvwxyz"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	symbols := "!@#$%^&*()-_=+[]{}:;,.?"

	if noAmbiguous {
		lower = stripChars(lower, "l")
		upper = stripChars(upper, "IO")
		digits = stripChars(digits, "01")
		symbols = stripChars(symbols, "|")
	}

	sets := []string{lower, upper, digits}
	if includeSymbols {
		sets = append(sets, symbols)
	}
	if length < len(sets) {
		return "", fmt.Errorf("length must be at least %d for selected character sets", len(sets))
	}

	password := make([]byte, 0, length)
	for _, set := range sets {
		ch, err := pickRandomChar(set)
		if err != nil {
			return "", err
		}
		password = append(password, ch)
	}

	all := strings.Join(sets, "")
	for len(password) < length {
		ch, err := pickRandomChar(all)
		if err != nil {
			return "", err
		}
		password = append(password, ch)
	}

	if err := shuffleBytes(password); err != nil {
		return "", err
	}
	return string(password), nil
}

func pickRandomChar(set string) (byte, error) {
	if len(set) == 0 {
		return 0, errors.New("empty character set")
	}
	idx, err := cryptoRandInt(len(set))
	if err != nil {
		return 0, err
	}
	return set[idx], nil
}

func shuffleBytes(data []byte) error {
	for i := len(data) - 1; i > 0; i-- {
		j, err := cryptoRandInt(i + 1)
		if err != nil {
			return err
		}
		data[i], data[j] = data[j], data[i]
	}
	return nil
}

func stripChars(input, toRemove string) string {
	if toRemove == "" {
		return input
	}
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if !strings.ContainsRune(toRemove, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cryptoRandInt(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("max must be > 0")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random index: %w", err)
	}
	return int(n.Int64()), nil
}

func printUsage() {
	fmt.Println(`keycraft - local-first offline password manager

Usage:
  keycraft <command> [options]

Commands:
  init             Initialize a new encrypted vault
  add              Add a password entry
  list             List vault entries
  get              Show one entry
  update           Update an entry by ID
  delete           Delete an entry by ID
  generate         Generate a strong random password
  change-master    Rotate master password
  help             Show this help text

Examples:
  keycraft init
  keycraft add --service github --username alice
  keycraft list --search git
  keycraft get --service github --username alice --show-password
  keycraft update --id <entry-id> --password -
  keycraft delete --id <entry-id>
  keycraft generate --length 32`)
}
