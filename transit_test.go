package libvault_test

import (
	"log"
	"testing"

	"github.com/gitirabassi/libvault"
	"github.com/stretchr/testify/assert"
)

func TestEncryptionDecryption(t *testing.T) {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		t.FailNow()
	}
	data := []byte("mysupersecret data also with spECIAL CHARS\n \t !!#@#@!@%ASASDA")
	transitEngine, err := cli.Transit("transit", "testingkey")
	if err != nil {
		log.Println("Creating transit backend and key:", err)
		t.FailNow()
	}
	encrypted, err := transitEngine.EncryptBytes(data)
	if err != nil {
		log.Println("Encrypting:", err)
		t.FailNow()
	}
	decrypted, err := transitEngine.DecryptToBytes(encrypted)
	if err != nil {
		log.Println("Decrypting:", err)
		t.FailNow()
	}
	assert.Equal(t, data, decrypted)
}
