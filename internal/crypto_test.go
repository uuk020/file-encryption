package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTempFile(t *testing.T, content []byte) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	assert.NoError(t, err)
	defer tmpFile.Close()

	_, err = tmpFile.Write(content)
	assert.NoError(t, err)

	return tmpFile.Name()
}

func readFileContent(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	return content
}

func assertFileEquals(t *testing.T, path1, path2 string) {
	t.Helper()
	content1, err := os.ReadFile(path1)
	assert.NoError(t, err)
	content2, err := os.ReadFile(path2)
	assert.NoError(t, err)
	assert.Equal(t, content1, content2)
}

func TestEncryptNew_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"4MB", 4 * 1024 * 1024},
		{"8MB", 8 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := make([]byte, tt.size)
			for i := range content {
				content[i] = byte(i % 256)
			}

			tmpFile := createTempFile(t, content)
			defer os.Remove(tmpFile)

			password := "testpassword123"

			err := EncryptFileNew(tmpFile, password)
			require.NoError(t, err)

			encryptedFile := tmpFile + ".xu"
			defer os.Remove(encryptedFile)

			_, err = os.Stat(encryptedFile)
			require.NoError(t, err)

			encryptedData := readFileContent(t, encryptedFile)
			require.True(t, IsNewFormat(encryptedData))

			err = DecryptFileNew(encryptedFile, password)
			require.NoError(t, err)

			decryptedContent := readFileContent(t, tmpFile)
			assert.Equal(t, content, decryptedContent)
		})
	}
}

func TestEncryptNew_MagicHeader(t *testing.T) {
	content := []byte("hello world")
	tmpFile := createTempFile(t, content)
	defer os.Remove(tmpFile)

	err := EncryptFileNew(tmpFile, "password")
	require.NoError(t, err)

	encryptedFile := tmpFile + ".xu"
	defer os.Remove(encryptedFile)

	encryptedData := readFileContent(t, encryptedFile)
	require.GreaterOrEqual(t, len(encryptedData), 4)
	assert.Equal(t, []byte(MagicHeader), encryptedData[:4])
}

func TestEncryptNew_DifferentPasswords(t *testing.T) {
	content := []byte("secret message")
	tmpFile := createTempFile(t, content)
	defer os.Remove(tmpFile)

	password1 := "password1"
	password2 := "password2"

	err := EncryptFileNew(tmpFile, password1)
	require.NoError(t, err)

	encryptedFile := tmpFile + ".xu"
	defer os.Remove(encryptedFile)

	encryptedData1 := readFileContent(t, encryptedFile)

	err = EncryptFileNew(tmpFile, password2)
	require.NoError(t, err)

	encryptedData2 := readFileContent(t, encryptedFile)

	assert.NotEqual(t, encryptedData1, encryptedData2)
}

func TestDecryptNew_WrongPassword(t *testing.T) {
	content := []byte("secret message")
	tmpFile := createTempFile(t, content)
	defer os.Remove(tmpFile)

	password := "correctpassword"
	wrongPassword := "wrongpassword"

	err := EncryptFileNew(tmpFile, password)
	require.NoError(t, err)

	encryptedFile := tmpFile + ".xu"
	defer os.Remove(encryptedFile)

	err = DecryptFileNew(encryptedFile, wrongPassword)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestDecryptNew_CorruptedFile(t *testing.T) {
	content := []byte("secret message that is long enough")
	tmpFile := createTempFile(t, content)
	defer os.Remove(tmpFile)

	password := "testpassword"

	err := EncryptFileNew(tmpFile, password)
	require.NoError(t, err)

	encryptedFile := tmpFile + ".xu"
	defer os.Remove(encryptedFile)

	encryptedData := readFileContent(t, encryptedFile)
	if len(encryptedData) > 60 {
		encryptedData[60] ^= 0xFF
	}

	err = os.WriteFile(encryptedFile, encryptedData, 0644)
	require.NoError(t, err)

	err = DecryptFileNew(encryptedFile, password)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestDecryptNew_TruncatedFile(t *testing.T) {
	content := []byte("secret message that is long enough to test truncation")
	tmpFile := createTempFile(t, content)
	defer os.Remove(tmpFile)

	password := "testpassword"

	err := EncryptFileNew(tmpFile, password)
	require.NoError(t, err)

	encryptedFile := tmpFile + ".xu"
	defer os.Remove(encryptedFile)

	encryptedData := readFileContent(t, encryptedFile)
	truncated := encryptedData[:len(encryptedData)-10]

	err = os.WriteFile(encryptedFile, truncated, 0644)
	require.NoError(t, err)

	err = DecryptFileNew(encryptedFile, password)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestCrypto_EncryptDecryptNew(t *testing.T) {
	content := []byte("test content for crypto round trip")
	tmpFile := createTempFile(t, content)
	defer os.Remove(tmpFile)

	password := "cryptopassword"

	err := EncryptFileNew(tmpFile, password)
	require.NoError(t, err)

	encryptedFile := tmpFile + ".xu"
	defer os.Remove(encryptedFile)

	err = DecryptFileNew(encryptedFile, password)
	require.NoError(t, err)

	decryptedContent := readFileContent(t, tmpFile)
	assert.Equal(t, content, decryptedContent)
}