package libvault

import (
	"fmt"
	"log"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

// Client is a simple yet minimal abstraction over the default api.Client from the original library
type Client struct {
	client *api.Client
}

// NewClient is in charge of creating a connection and validating that connection on the start before even starting to attemp anythign
func NewClient() (*Client, error) {
	vaultClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	cli := &Client{
		client: vaultClient,
	}
	status, err := vaultClient.Sys().InitStatus()
	if err != nil {
		return nil, err
	}
	if status != true {
		return nil, fmt.Errorf("Vault not ready yet")
	}
	return cli, nil
}

// GetAPIClient returns the vault api.Client form the original sdk
func (c *Client) GetAPIClient() *api.Client {
	return c.client
}

// UnmarshalSecret is a usefull utility to make types out of vault secrets
func UnmarshalSecret(secret *api.Secret, output interface{}, kv2style bool) error {
	return unmarshalSecret(secret, output, kv2style)
}

func (c *Client) writeOp(path string, input, output interface{}, kv2style bool) error {
	rawIn, err := marshalSecret(input, kv2style)
	rawOut, err := c.client.Logical().Write(path, rawIn)
	if err != nil {
		return err
	}
	if output == nil {
		return nil
	}
	return unmarshalSecret(rawOut, output, false)
}

func (c *Client) readOp(path string, output interface{}, kv2style bool) error {
	raw, err := c.client.Logical().Read(path)
	if err != nil {
		return err
	}
	return unmarshalSecret(raw, output, kv2style)
}

func (c *Client) deleteOp(path string) error {
	_, err := c.client.Logical().Delete(path)
	return err
}

// ListOutput represent the kind of secret you get after a list operation
type ListOutput struct {
	Keys []string `mapstructure:"keys"`
}

// ListOp returns the full path of the secret
func (c *Client) listOp(path string) ([]string, error) {
	rawList, err := c.client.Logical().List(path)
	if err != nil {
		return nil, err
	}
	list := &ListOutput{}
	err = unmarshalSecret(rawList, list, false)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for _, key := range list.Keys {
		paths = append(paths, fmt.Sprintf("%s/%s", path, key))
	}
	return paths, nil
}

func marshalSecret(input interface{}, kv2style bool) (map[string]interface{}, error) {
	rawIn := make(map[string]interface{}, 0)
	err := mapstructure.Decode(input, &rawIn)
	if err != nil {
		return nil, err
	}
	if kv2style {
		v2map := make(map[string]interface{}, 0)
		v2map["data"] = rawIn
		return v2map, nil
	}
	return rawIn, nil
}

func unmarshalSecret(secret *api.Secret, output interface{}, kv2style bool) error {
	if secret == nil {
		return fmt.Errorf("Secret is nil")
	}
	if secret.Data == nil {
		return fmt.Errorf("The secret doesn't contain any data")
	}

	if kv2style {
		kv2secret, ok := secret.Data["data"]
		if !ok {
			return fmt.Errorf("not a kv2style secret")
		}
		if kv2secret != nil {
			secretContent, ok := kv2secret.(map[string]interface{})
			if !ok {
				log.Println("Couln't cast the 'data' object: are you sure this is a KV2? are you using 'data' as field in you KV1 secret backend")
				return fmt.Errorf("couln't cast the 'data' coming from the KV2 of Vault to map[string]interface{}")
			}
			err := mapstructure.Decode(secretContent, &output)
			if err != nil {
				return err
			}
			return nil
		}
	}

	err := mapstructure.Decode(secret.Data, &output)
	if err != nil {
		return err
	}
	return nil
}
