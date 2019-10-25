package libvault

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/vault/api"
)

// KV represents the KV store in vault
type KV struct {
	c       *Client
	path    string
	v2style bool
}

// KV makes the user enter in the KV space
func (c *Client) KV(path string, enableKV2 bool, createIfDoesntExist bool) (*KV, error) {
	version := 1
	if enableKV2 {
		version = 2
	}
	mountOptions := &api.MountInput{
		Type:        "kv",
		Description: defaultMountDescription,
		Options: map[string]string{
			"version": strconv.Itoa(version),
		},
	}
	err := c.mount(path, mountOptions, createIfDoesntExist)
	if err != nil {
		return nil, err
	}
	return &KV{
		c:       c,
		path:    path,
		v2style: enableKV2,
	}, nil
}

// Put is a parity funcion with `vault kv put`
func (k *KV) Put(secretName string, input interface{}) error {
	secretPath := ""
	if k.v2style {
		secretPath = fmt.Sprintf("%s/data/%s", k.path, secretName)
	} else {
		secretPath = fmt.Sprintf("%s/%s", k.path, secretName)
	}
	return k.c.writeOp(secretPath, input, nil, k.v2style)
}

// Get is the parithy function with `vualt kv get`
func (k *KV) Get(secretName string, output interface{}) error {
	secretPath := ""
	if k.v2style {
		secretPath = fmt.Sprintf("%s/data/%s", k.path, secretName)
	} else {
		secretPath = fmt.Sprintf("%s/%s", k.path, secretName)
	}
	return k.c.readOp(secretPath, output, k.v2style)
}

// List is the parithy function with `vualt kv list`
func (k *KV) List(secretName string) ([]string, error) {
	secretPath := ""
	if k.v2style {
		secretPath = fmt.Sprintf("%s/data/%s", k.path, secretName)
	} else {
		secretPath = fmt.Sprintf("%s/%s", k.path, secretName)
	}
	return k.c.listOp(secretPath)
}

// Delete is the parity function with `vuault kv delete`
func (k *KV) Delete(secretName string) error {
	secretPath := ""
	if k.v2style {
		secretPath = fmt.Sprintf("%s/data/%s", k.path, secretName)
	} else {
		secretPath = fmt.Sprintf("%s/%s", k.path, secretName)
	}
	return k.c.deleteOp(secretPath)
}
