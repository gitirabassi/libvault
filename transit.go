package libvault

import (
	"encoding/base64"
	"fmt"
	"path/filepath"

	"github.com/hashicorp/vault/api"
)

// Transit represents the transit secret backend in vault
type Transit struct {
	c       *Client
	path    string
	keyName string
}

// Key is how a new key is created/configured in vault
type Key struct {
	Type string `mapstructure:"type"`
}

// Transit makes the user enter in the Transit space
func (c *Client) Transit(path, keyName string) (*Transit, error) {
	//TODO: check if it already exist
	err := c.client.Sys().Mount(path, &api.MountInput{
		Type:        "transit",
		Description: "created with libvault",
	})
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(path, "keys", keyName)
	keyInput := &Key{
		//TODO: being able to change this
		Type: "rsa-4096",
	}
	err = c.writeOp(keyPath, keyInput, nil, false)
	if err != nil {
		return nil, err
	}
	err = c.readOp(keyPath, nil, false)
	if err != nil {
		return nil, err
	}
	return &Transit{
		c:       c,
		path:    path,
		keyName: keyName,
	}, nil
}

// Unencrypted is the plaintext side!
type Unencrypted struct {
	Plaintext string `mapstructure:"plaintext"`
}

// Encrypted is used to unmarshal ouput from the Encrypt or input for the Decrypt function
type Encrypted struct {
	Ciphertext string `mapstructure:"ciphertext"`
}

// EncryptBytes is used to encrypt data that is already serialized
func (t *Transit) EncryptBytes(plaintext []byte) (string, error) {
	return t.encryptBytes(plaintext)
}

func (t *Transit) encryptBytes(plaintext []byte) (string, error) {
	encryptPath := filepath.Join(t.path, "encrypt", t.keyName)
	input := &Unencrypted{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	output := &Encrypted{}
	err := t.c.writeOp(encryptPath, input, output, false)
	if err != nil {
		return "", err
	}
	return output.Ciphertext, nil
}

// DecryptToBytes is used to encrypt data that is already serialized
func (t *Transit) DecryptToBytes(ciphertext string) ([]byte, error) {
	return t.decryptToBytes(ciphertext)
}

func (t *Transit) decryptToBytes(ciphertext string) ([]byte, error) {
	decryptPath := filepath.Join(t.path, "decrypt", t.keyName)
	input := &Encrypted{
		Ciphertext: ciphertext,
	}
	output := &Unencrypted{}
	err := t.c.writeOp(decryptPath, input, output, false)
	if err != nil {
		return nil, err
	}
	bytes, err := base64.StdEncoding.DecodeString(output.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("Couldn't decode base64 plaintext: %v", err)
	}
	return bytes, nil
}

// func (t *Transit) createVaultTransitAndKey() error {
// 	err = cli.Sys().Mount(key.TransitBackend, &api.MountInput{
// 		Type:        "transit",
// 		Description: "created with libvault",
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	path := filepath.Join(key.TransitBackend, "keys", key.KeyName)
// 	payload := make(map[string]interface{})
// 	payload["type"] = "rsa-4096"
// 	_, err = cli.Logical().Write(path, payload)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = cli.Logical().Read(path)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
