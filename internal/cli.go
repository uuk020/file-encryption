package internal

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// CLIConfig holds the parsed CLI configuration
type CLIConfig struct {
	Mode    string
	Password string
	File    string
	Dir     string
	Delete  bool
}

// ReadPassword reads a password from terminal without echo
func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(password), nil
}

// PromptPassword prompts for password interactively (no echo)
func PromptPassword(prompt string) (string, error) {
	return ReadPassword(prompt)
}

// PromptPasswordConfirmation prompts twice for encryption and verifies match
func PromptPasswordConfirmation() (string, error) {
	password, err := PromptPassword("Enter password: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	confirm, err := PromptPassword("Confirm password: ")
	if err != nil {
		return "", fmt.Errorf("failed to read confirmation: %w", err)
	}

	if password != confirm {
		return "", errors.New("passwords do not match")
	}

	return password, nil
}

// NormalizeMode converts old mode names to new ones
// "encryption" -> "encrypt", "decryption" -> "decrypt"
// Also accepts new names directly
func NormalizeMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "encrypt", "encryption":
		return "encrypt", nil
	case "decrypt", "decryption":
		return "decrypt", nil
	default:
		return "", fmt.Errorf("mode must be 'encrypt' or 'decrypt', got '%s'", mode)
	}
}

// ValidateCLI validates the CLI configuration and returns an error if invalid
func ValidateCLI(config CLIConfig) error {
	// Check that exactly one of file or dir is specified
	hasFile := config.File != ""
	hasDir := config.Dir != ""

	if !hasFile && !hasDir {
		return errors.New("file or directory is required")
	}

	if hasFile && hasDir {
		return errors.New("file or directory are required (not both)")
	}

	// Validate mode
	_, err := NormalizeMode(config.Mode)
	if err != nil {
		return err
	}

	return nil
}

// ParseFlags parses command-line flags and returns a CLIConfig
func ParseFlags(args []string) (*CLIConfig, error) {
	fs := flag.NewFlagSet("fileEncryption", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: fileEncryption [options]\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}

	mode := fs.String("m", "encrypt", "encryption or decryption mode (encrypt/decrypt or encryption/decryption)")
	password := fs.String("p", "", "input password, same password will be used to encrypt and decrypt")
	file := fs.String("f", "", "input file, encrypted or decrypted file")
	dir := fs.String("d", "", "input directory, all files in the directory will be encrypted or decrypted")
	deleteFlag := fs.Bool("r", false, "delete original files after encryption/decryption")
	deleteLong := fs.Bool("delete", false, "delete original files after encryption/decryption")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil, err
		}
		return nil, err
	}

	config := &CLIConfig{
		Mode:    *mode,
		Password: *password,
		File:    *file,
		Dir:     *dir,
		Delete:  *deleteFlag || *deleteLong,
	}

	return config, nil
}

// GetPassword returns the password, prompting interactively if empty
func GetPassword(config CLIConfig, isEncryption bool) (string, error) {
	if config.Password != "" {
		return config.Password, nil
	}

	// Interactive mode
	if isEncryption {
		return PromptPasswordConfirmation()
	}
	return PromptPassword("Enter password: ")
}