package libvault_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	transitEngine, err := cli.Transit("transit", "testingkey", true)
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
	transitEngine, err := cli.Transit("transitv2", "testsign", true)
	if err != nil {
		log.Println("Creating transit backend and key:", err)
		t.Fail()
		return
	}
	_, err = cli.Transit("transitv2", "testsign", true)
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

// func TestSignVerifyWithoutPrefix(t *testing.T) {
// 	cli, err := libvault.NewClient()
// 	if err != nil {
// 		log.Println(err)
// 		t.Fail()
// 		return
// 	}
// 	data := "mysupersecret 2312314120240980data also with spECIAL CHARS\n \t !!#@#@!@%ASASDA"
// 	transitEngine, err := cli.Transit("transitv2", "testsign")
// 	if err != nil {
// 		log.Println("Creating transit backend and key:", err)
// 		t.Fail()
// 		return
// 	}
// 	signature, err := transitEngine.Sign(data)
// 	if err != nil {
// 		log.Println("Singing:", err)
// 		t.Fail()
// 		return
// 	}
// 	trimmedSignature := libvault.CutVaultPrefix(signature)
// 	err = transitEngine.VerifySignature(data, trimmedSignature)
// 	if err != nil {
// 		log.Println("Verifying:", err)
// 		t.Fail()
// 		return
// 	}
// }

func TestHMACVerify(t *testing.T) {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		t.Fail()
		return
	}
	data := "mysupersecret 2312314120240980data also with spECIAL CHARS\n \t !!#@#@!@%ASASDA"
	transitEngine, err := cli.Transit("transitv3", "testsign", true)
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

func TestPubKey(t *testing.T) {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		t.Fail()
		return
	}
	transitEngine, err := cli.Transit("transitv4", "testsign", true)
	if err != nil {
		log.Println("Creating transit backend and key:", err)
		t.Fail()
		return
	}
	publicKey, err := transitEngine.GetPublicKey()
	if err != nil {
		log.Println("Getting public key:", err)
		t.Fail()
		return
	}
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		log.Println("failed to parse PEM block containing the public key")
		t.Fail()
		return
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Println("Parsing public key:", err)
		t.Fail()
		return
	}
	keyType := transitEngine.KeyType()
	switch keyType {
	case "rsa-2048", "rsa-4096":
		_, ok := pub.(*rsa.PublicKey)
		if !ok {
			log.Println("Key cannot be casted of type rsa.PublicKey:")
			t.Fail()
			return
		}
	case "ecdsa-p256":
		_, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			log.Println("Key cannot be casted of type ecdsa.PublicKey:")
			t.Fail()
			return
		}
	default:
		log.Println("Wrong type of tranit key type:")
		t.Fail()
	}
}
