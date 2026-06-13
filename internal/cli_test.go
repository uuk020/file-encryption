package internal

import (
	"errors"
	"testing"
)

func TestNormalizeMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{"encrypt alias", "encryption", "encrypt", false},
		{"encrypt new", "encrypt", "encrypt", false},
		{"encrypt uppercase", "ENCRYPT", "encrypt", false},
		{"encrypt mixed case", "Encrypt", "encrypt", false},
		{"decryption alias", "decryption", "decrypt", false},
		{"decrypt new", "decrypt", "decrypt", false},
		{"decrypt uppercase", "DECRYPT", "decrypt", false},
		{"decrypt mixed case", "Decrypt", "decrypt", false},
		{"with spaces", "  encrypt  ", "encrypt", false},
		{"invalid mode", "invalid", "", true},
		{"empty string", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("NormalizeMode(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateCLI(t *testing.T) {
	tests := []struct {
		name    string
		config  CLIConfig
		wantErr error
	}{
		{
			name: "valid with file",
			config: CLIConfig{
				Mode:    "encrypt",
				Password: "test",
				File:    "test.txt",
			},
			wantErr: nil,
		},
		{
			name: "valid with dir",
			config: CLIConfig{
				Mode:    "decrypt",
				Password: "test",
				Dir:     "testdir",
			},
			wantErr: nil,
		},
		{
			name: "missing file and dir",
			config: CLIConfig{
				Mode:     "encrypt",
				Password: "test",
			},
			wantErr: errors.New("file or directory is required"),
		},
		{
			name: "both file and dir specified",
			config: CLIConfig{
				Mode:     "encrypt",
				Password: "test",
				File:     "test.txt",
				Dir:      "testdir",
			},
			wantErr: errors.New("file or directory are required (not both)"),
		},
		{
			name: "invalid mode",
			config: CLIConfig{
				Mode:    "invalid",
				Password: "test",
				File:    "test.txt",
			},
			wantErr: errors.New("mode must be 'encrypt' or 'decrypt', got 'invalid'"),
		},
		{
			name: "empty mode",
			config: CLIConfig{
				Mode:    "",
				Password: "test",
				File:    "test.txt",
			},
			wantErr: errors.New("mode must be 'encrypt' or 'decrypt', got ''"),
		},
		{
			name: "encryption alias accepted",
			config: CLIConfig{
				Mode:    "encryption",
				Password: "test",
				File:    "test.txt",
			},
			wantErr: nil,
		},
		{
			name: "decryption alias accepted",
			config: CLIConfig{
				Mode:    "decryption",
				Password: "test",
				File:    "test.txt",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCLI(tt.config)
			if tt.wantErr == nil && err != nil {
				t.Errorf("ValidateCLI() unexpected error: %v", err)
				return
			}
			if tt.wantErr != nil && err == nil {
				t.Errorf("ValidateCLI() expected error %v, got nil", tt.wantErr)
				return
			}
			if tt.wantErr != nil && err != nil && tt.wantErr.Error() != err.Error() {
				t.Errorf("ValidateCLI() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantMode       string
		wantPassword   string
		wantFile       string
		wantDir        string
		wantDelete     bool
		wantErr        bool
	}{
		{
			name:         "encrypt mode",
			args:         []string{"-m", "encrypt"},
			wantMode:     "encrypt",
			wantPassword: "",
			wantFile:     "",
			wantDir:      "",
			wantDelete:    false,
			wantErr:      false,
		},
		{
			name:         "encryption alias",
			args:         []string{"-m", "encryption"},
			wantMode:     "encryption",
			wantPassword: "",
			wantFile:     "",
			wantDir:      "",
			wantDelete:    false,
			wantErr:      false,
		},
		{
			name:         "decrypt mode",
			args:         []string{"-m", "decrypt"},
			wantMode:     "decrypt",
			wantPassword: "",
			wantFile:     "",
			wantDir:      "",
			wantDelete:    false,
			wantErr:      false,
		},
		{
			name:         "decryption alias",
			args:         []string{"-m", "decryption"},
			wantMode:     "decryption",
			wantPassword: "",
			wantFile:     "",
			wantDir:      "",
			wantDelete:    false,
			wantErr:      false,
		},
		{
			name:         "with password",
			args:         []string{"-m", "encrypt", "-p", "mypassword"},
			wantMode:     "encrypt",
			wantPassword: "mypassword",
			wantFile:     "",
			wantDir:      "",
			wantDelete:    false,
			wantErr:      false,
		},
		{
			name:         "with file",
			args:         []string{"-m", "encrypt", "-f", "test.txt"},
			wantMode:     "encrypt",
			wantPassword: "",
			wantFile:     "test.txt",
			wantDir:      "",
			wantDelete:    false,
			wantErr:      false,
		},
		{
			name:         "with directory",
			args:         []string{"-m", "encrypt", "-d", "testdir"},
			wantMode:     "encrypt",
			wantPassword: "",
			wantFile:     "",
			wantDir:      "testdir",
			wantDelete:    false,
			wantErr:      false,
		},
		{
			name:         "with delete short flag",
			args:         []string{"-m", "encrypt", "-r"},
			wantMode:     "encrypt",
			wantPassword: "",
			wantFile:     "",
			wantDir:      "",
			wantDelete:    true,
			wantErr:      false,
		},
		{
			name:         "with delete long flag",
			args:         []string{"-m", "encrypt", "--delete"},
			wantMode:     "encrypt",
			wantPassword: "",
			wantFile:     "",
			wantDir:      "",
			wantDelete:    true,
			wantErr:      false,
		},
		{
			name:         "all flags",
			args:         []string{"-m", "encrypt", "-p", "pass", "-f", "test.txt", "-r"},
			wantMode:     "encrypt",
			wantPassword: "pass",
			wantFile:     "test.txt",
			wantDir:      "",
			wantDelete:    true,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseFlags(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if config == nil {
				return
			}
			if config.Mode != tt.wantMode {
				t.Errorf("ParseFlags() Mode = %q, want %q", config.Mode, tt.wantMode)
			}
			if config.Password != tt.wantPassword {
				t.Errorf("ParseFlags() Password = %q, want %q", config.Password, tt.wantPassword)
			}
			if config.File != tt.wantFile {
				t.Errorf("ParseFlags() File = %q, want %q", config.File, tt.wantFile)
			}
			if config.Dir != tt.wantDir {
				t.Errorf("ParseFlags() Dir = %q, want %q", config.Dir, tt.wantDir)
			}
			if config.Delete != tt.wantDelete {
				t.Errorf("ParseFlags() Delete = %v, want %v", config.Delete, tt.wantDelete)
			}
		})
	}
}