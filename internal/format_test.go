package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMagicHeader(t *testing.T) {
	if MagicHeader != "XU2\x00" {
		t.Errorf("MagicHeader = %q, want \"XU2\\x00\"", MagicHeader)
	}
}

func TestCurrentVersion(t *testing.T) {
	if CurrentVersion != 0x01 {
		t.Errorf("CurrentVersion = 0x%02x, want 0x01", CurrentVersion)
	}
}

func TestChunkSize(t *testing.T) {
	if ChunkSize != 4*1024*1024 {
		t.Errorf("ChunkSize = %d, want %d", ChunkSize, 4*1024*1024)
	}
}

func TestFileHeaderEncodeDecode(t *testing.T) {
	salt := []byte("test-salt-16b")
	hdr := FileHeader{
		Magic:       [4]byte{'X', 'U', '2', 0x00},
		Version:     CurrentVersion,
		SaltLen:     uint16(len(salt)),
		Salt:        salt,
		Argon2Time:  1,
		Argon2Memory: 64 * 1024,
		Argon2Threads: 4,
		ChunkSize:   ChunkSize,
	}

	data, err := hdr.EncodeHeader()
	if err != nil {
		t.Fatalf("EncodeHeader() error = %v", err)
	}

	// Verify magic is first 4 bytes
	if !bytes.Equal(data[:4], []byte(MagicHeader)) {
		t.Errorf("Magic bytes = %v, want %v", data[:4], []byte(MagicHeader))
	}

	// Decode and verify
	decoded, err := DecodeHeader(data)
	if err != nil {
		t.Fatalf("DecodeHeader() error = %v", err)
	}

	if decoded.Version != hdr.Version {
		t.Errorf("Version = %d, want %d", decoded.Version, hdr.Version)
	}
	if decoded.SaltLen != hdr.SaltLen {
		t.Errorf("SaltLen = %d, want %d", decoded.SaltLen, hdr.SaltLen)
	}
	if !bytes.Equal(decoded.Salt, hdr.Salt) {
		t.Errorf("Salt = %v, want %v", decoded.Salt, hdr.Salt)
	}
	if decoded.Argon2Time != hdr.Argon2Time {
		t.Errorf("Argon2Time = %d, want %d", decoded.Argon2Time, hdr.Argon2Time)
	}
	if decoded.Argon2Memory != hdr.Argon2Memory {
		t.Errorf("Argon2Memory = %d, want %d", decoded.Argon2Memory, hdr.Argon2Memory)
	}
	if decoded.Argon2Threads != hdr.Argon2Threads {
		t.Errorf("Argon2Threads = %d, want %d", decoded.Argon2Threads, hdr.Argon2Threads)
	}
	if decoded.ChunkSize != hdr.ChunkSize {
		t.Errorf("ChunkSize = %d, want %d", decoded.ChunkSize, hdr.ChunkSize)
	}
}

func TestFileHeaderEncodeDecodeVaryingSaltLen(t *testing.T) {
	testCases := []struct {
		name     string
		saltLen  int
	}{
		{"16 bytes salt", 16},
		{"32 bytes salt", 32},
		{"64 bytes salt", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			salt := make([]byte, tc.saltLen)
			for i := range salt {
				salt[i] = byte(i)
			}

			hdr := FileHeader{
				Magic:        [4]byte{'X', 'U', '2', 0x00},
				Version:      CurrentVersion,
				SaltLen:      uint16(len(salt)),
				Salt:         salt,
				Argon2Time:   2,
				Argon2Memory: 128 * 1024,
				Argon2Threads: 2,
				ChunkSize:    ChunkSize,
			}

			data, err := hdr.EncodeHeader()
			if err != nil {
				t.Fatalf("EncodeHeader() error = %v", err)
			}

			decoded, err := DecodeHeader(data)
			if err != nil {
				t.Fatalf("DecodeHeader() error = %v", err)
			}

			if !bytes.Equal(decoded.Salt, hdr.Salt) {
				t.Errorf("Salt mismatch for saltLen=%d", tc.saltLen)
			}
		})
	}
}

func TestChunkHeaderEncodeDecode(t *testing.T) {
	ch := ChunkHeader{
		Nonce:         [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		CiphertextLen: 1024,
	}

	data, err := ch.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	if len(data) != 16 {
		t.Errorf("len(data) = %d, want 16", len(data))
	}

	decoded, err := DecodeChunkHeader(data)
	if err != nil {
		t.Fatalf("DecodeChunkHeader() error = %v", err)
	}

	if decoded.CiphertextLen != ch.CiphertextLen {
		t.Errorf("CiphertextLen = %d, want %d", decoded.CiphertextLen, ch.CiphertextLen)
	}
	if !bytes.Equal(decoded.Nonce[:], ch.Nonce[:]) {
		t.Errorf("Nonce = %v, want %v", decoded.Nonce, ch.Nonce)
	}
}

func TestIsNewFormat(t *testing.T) {
	// New format with correct magic
	newFormatData := []byte{'X', 'U', '2', 0x00, 0x01}
	if !IsNewFormat(newFormatData) {
		t.Error("IsNewFormat() = false for valid new format data")
	}

	// Old format (no magic)
	oldFormatData := []byte("this is old encrypted data")
	if IsNewFormat(oldFormatData) {
		t.Error("IsNewFormat() = true for old format data")
	}

	// Too short
	shortData := []byte{'X', 'U'}
	if IsNewFormat(shortData) {
		t.Error("IsNewFormat() = true for short data")
	}

	// Wrong magic
	wrongMagic := []byte{'Y', 'U', '2', 0x00}
	if IsNewFormat(wrongMagic) {
		t.Error("IsNewFormat() = true for wrong magic")
	}
}

func TestDecodeHeaderTooShort(t *testing.T) {
	shortData := []byte{'X', 'U', '2', 0x00} // Only magic, no version
	_, err := DecodeHeader(shortData)
	if err == nil {
		t.Error("DecodeHeader() expected error for short data")
	}
}

func TestDecodeChunkHeaderTooShort(t *testing.T) {
	shortData := make([]byte, 10) // Too short for 12-byte nonce + 4-byte len
	_, err := DecodeChunkHeader(shortData)
	if err == nil {
		t.Error("DecodeChunkHeader() expected error for short data")
	}
}

func TestFileHeaderSize(t *testing.T) {
	// Header: magic(4) + version(1) + saltLen(2) + salt(variable) + argon2time(4) + argon2memory(4) + argon2threads(1) + chunkSize(4)
	// For 16-byte salt: 4 + 1 + 2 + 16 + 4 + 4 + 1 + 4 = 36
	salt := make([]byte, 16)
	hdr := FileHeader{
		Magic:        [4]byte{'X', 'U', '2', 0x00},
		Version:      CurrentVersion,
		SaltLen:      uint16(len(salt)),
		Salt:         salt,
		Argon2Time:   1,
		Argon2Memory: 64 * 1024,
		Argon2Threads: 4,
		ChunkSize:    ChunkSize,
	}

	data, err := hdr.EncodeHeader()
	if err != nil {
		t.Fatalf("EncodeHeader() error = %v", err)
	}

	// Verify big-endian encoding for multi-byte fields
	versionOffset := 4
	if data[versionOffset] != CurrentVersion {
		t.Errorf("Version at offset %d = 0x%02x, want 0x%02x", versionOffset, data[versionOffset], CurrentVersion)
	}

	saltLenOffset := 5
	saltLen := binary.BigEndian.Uint16(data[saltLenOffset : saltLenOffset+2])
	if saltLen != uint16(len(salt)) {
		t.Errorf("SaltLen at offset %d = %d, want %d", saltLenOffset, saltLen, len(salt))
	}
	_ = data // silence unused warning
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, 0o600))
}

func newFormatFileContent(extra ...byte) []byte {
	buf := make([]byte, 0, 4+len(extra))
	buf = append(buf, []byte(MagicHeader)...)
	buf = append(buf, extra...)
	return buf
}

func TestDetectFormat_New(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.xu")
	writeFile(t, path, newFormatFileContent(0x01, 0x02, 0x03, 0x04))

	got, err := DetectFormat(path)
	require.NoError(t, err)
	assert.Equal(t, FormatNew, got)
}

func TestDetectFormat_Legacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.xu")
	writeFile(t, path, []byte("\x8b\x3e\x06\xee some legacy ciphertext"))

	got, err := DetectFormat(path)
	require.NoError(t, err)
	assert.Equal(t, FormatLegacy, got)
}

func TestDetectFormat_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.xu")
	writeFile(t, path, nil)

	got, err := DetectFormat(path)
	assert.Equal(t, "", got)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrFileTooSmall), "expected ErrFileTooSmall, got %v", err)
}

func TestDetectFormat_TooSmall(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"1 byte", 1},
		{"2 bytes", 2},
		{"3 bytes", 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "small.xu")
			writeFile(t, path, bytes.Repeat([]byte{0xAB}, tc.size))

			got, err := DetectFormat(path)
			assert.Equal(t, "", got)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrFileTooSmall), "expected ErrFileTooSmall, got %v", err)
		})
	}
}

func TestDetectFormat_NonExistent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does_not_exist.xu")

	got, err := DetectFormat(missing)
	assert.Equal(t, "", got)
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "expected not-exist error, got %v", err)
}

func TestDetectFormat_Directory(t *testing.T) {
	dir := t.TempDir()

	got, err := DetectFormat(dir)
	assert.Equal(t, "", got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory")
}

func TestDetectFormat_SymlinkToNewFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.xu")
	writeFile(t, target, newFormatFileContent(0x10, 0x20, 0x30, 0x40))

	link := filepath.Join(dir, "link.xu")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	got, err := DetectFormat(link)
	require.NoError(t, err)
	assert.Equal(t, FormatNew, got)
}

func TestDetectFormat_SymlinkToLegacyFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.xu")
	writeFile(t, target, []byte("legacy data with no magic"))

	link := filepath.Join(dir, "link.xu")
	require.NoError(t, os.Symlink(target, link))

	got, err := DetectFormat(link)
	require.NoError(t, err)
	assert.Equal(t, FormatLegacy, got)
}

func TestDetectFormat_BrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "broken.xu")
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing.xu"), link))

	got, err := DetectFormat(link)
	assert.Equal(t, "", got)
	require.Error(t, err)
}

func TestDecryptFileAuto_RoutesToLegacy(t *testing.T) {
	dir := t.TempDir()
	plaintextPath := filepath.Join(dir, "payload.txt")
	plaintext := []byte("legacy round-trip via auto-routing!")
	require.NoError(t, os.WriteFile(plaintextPath, plaintext, 0o600))

	password := "secret"
	key := GenerateKey(password, 16)
	require.NoError(t, EncryptFileLegacy(plaintextPath, key))

	encryptedPath := plaintextPath + ".xu"
	t.Cleanup(func() { _ = os.Remove(encryptedPath) })
	t.Cleanup(func() { _ = os.Remove(plaintextPath) })

	require.NoError(t, os.Remove(plaintextPath))

	require.NoError(t, DecryptFileAuto(encryptedPath, password))

	got := readFileContent(t, plaintextPath)
	assert.Equal(t, plaintext, got)
}

func TestDecryptFileAuto_RoutesToNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new_payload.xu")
	writeFile(t, path, newFormatFileContent(0x01, 0x00, 0x00, 0x10))

	err := DecryptFileAuto(path, "anypassword")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read remaining header")
}

func TestDecryptFileAuto_NonExistent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.xu")
	err := DecryptFileAuto(missing, "pw")
	require.Error(t, err)
	assert.True(t, os.IsNotExist(err), "expected not-exist error, got %v", err)
}