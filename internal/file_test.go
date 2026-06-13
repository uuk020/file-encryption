package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacy_EncryptDecryptRoundTrip(t *testing.T) {
	content := []byte("Hello, this is a test message for legacy encryption!")
	tmpFile := createTempFile(t, content)

	key := GenerateKey("testpassword", 16)

	err := EncryptFileLegacy(tmpFile, key)
	require.NoError(t, err)

	encryptedFile := tmpFile + ".xu"
	defer os.Remove(encryptedFile)

	_, err = os.Stat(encryptedFile)
	require.NoError(t, err)

	err = DecryptFileLegacy(encryptedFile, key)
	require.NoError(t, err)

	decryptedContent := readFileContent(t, tmpFile)
	assert.Equal(t, content, decryptedContent)
}

func TestLegacy_GenerateKeyDeterministic(t *testing.T) {
	key1 := GenerateKey("test", 16)
	key2 := GenerateKey("test", 16)

	assert.Equal(t, key1, key2)
	assert.Equal(t, []byte("4621d373cade4e83"), key1)
}

func TestLegacy_RegressionFixture(t *testing.T) {
	// Fixture generated with legacy code: plaintext="Hello, legacy format!", key=GenerateKey("test",16)
	fixtureCiphertext := []byte{
		0x8b, 0x3e, 0x06, 0xee, 0x07, 0x6d, 0x02, 0x9d,
		0x09, 0x36, 0x40, 0xc1, 0x7c, 0xf3, 0xf3, 0xbc,
		0x09, 0x85, 0x95, 0x27, 0x06, 0x5c, 0xba, 0x1d,
		0x64, 0xfe, 0x37, 0x87, 0xa7, 0x31, 0x39, 0x2f,
	}
	expectedPlaintext := []byte("Hello, legacy format!")
	key := []byte("4621d373cade4e83")

	tmpFile, err := os.CreateTemp("", "fixture_*.xu")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer os.Remove(tmpFile.Name()[:len(tmpFile.Name())-3])

	_, err = tmpFile.Write(fixtureCiphertext)
	require.NoError(t, err)
	tmpFile.Close()

	err = DecryptFileLegacy(tmpFile.Name(), key)
	require.NoError(t, err)

	decryptedFile := tmpFile.Name()[:len(tmpFile.Name())-3]
	decryptedContent := readFileContent(t, decryptedFile)
	assert.Equal(t, expectedPlaintext, decryptedContent)
}
