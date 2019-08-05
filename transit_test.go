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

func TestSignVerify(t *testing.T) {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		t.Fail()
		return
	}
	data := "mysupersecret 2312314120240980data also with spECIAL CHARS\n \t !!#@#@!@%ASASDA"
	transitEngine, err := cli.Transit("transitv2", "testsign")
	if err != nil {
		log.Println("Creating transit backend and key:", err)
		t.Fail()
		return
	}
	signature, err := transitEngine.Sign(data)
	if err != nil {
		log.Println("Singing:", err)
		t.Fail()
		return
	}
	err = transitEngine.VerifySignature(data, signature)
	if err != nil {
		log.Println("Verifying:", err)
		t.Fail()
		return
	}
}

func TestHMACVerify(t *testing.T) {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		t.Fail()
		return
	}
	data := "mysupersecret 2312314120240980data also with spECIAL CHARS\n \t !!#@#@!@%ASASDA"
	transitEngine, err := cli.Transit("transitv3", "testsign")
	if err != nil {
		log.Println("Creating transit backend and key:", err)
		t.Fail()
		return
	}
	publicKey, err := transitEngine.GetPublicKey()
	if err != nil {
		log.Println("HMAC:", err)
		t.Fail()
		return
	}
	log.Println(publicKey)

	hash, err := transitEngine.HMAC(data)
	if err != nil {
		log.Println("HMAC:", err)
		t.Fail()
		return
	}

	err = transitEngine.VerifyHMAC(data, hash)
	if err != nil {
		log.Println("Verifying:", err)
		t.Fail()
		return
	}
}
