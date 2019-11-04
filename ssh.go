package libvault

import (
	"path"

	"github.com/hashicorp/vault/api"
)

// SSH identifies a new SSH secret engine
type SSH struct {
	c    *Client
	path string
}

//SSHInit is used to initialize a SSH secret backend with CA key_type
type SSHInit struct {
	GenerateSigningKey bool `mapstructure:"generate_signing_key"`
}

// SSHRole is used to create a new role for ssh CA key_type
type SSHRole struct {
	AllowUserCertificates bool              `mapstructure:"allow_user_certificates"`
	AllowedUsers          string            `mapstructure:"allowed_users"`
	DefaultExtensions     map[string]string `mapstructure:"default_extensions"`
	AllowedExtenstion     string            `mapstructure:"allowed_extensions"`
	KeyType               string            `mapstructure:"key_type"`
	DefaultUser           string            `mapstructure:"default_user"`
	TTL                   string            `mapstructure:"ttl"`
	MaxTTL                string            `mapstructure:"max_ttl"`
}

// SSH makes the user enter in the SSH space
func (c *Client) SSH(mountPath string, createIfDoesntExist bool) (*SSH, error) {
	mountOptions := &api.MountInput{
		Type:        "ssh",
		Description: defaultMountDescription,
	}
	err := c.mount(mountPath, mountOptions, createIfDoesntExist)
	if err != nil {
		return nil, err
	}
	init := &SSHInit{
		GenerateSigningKey: true,
	}
	initPath := path.Join(mountPath, "config/ca")
	err = c.writeOp(initPath, init, nil, false)
	if err != nil {
		return nil, err
	}
	defaultRolePath := path.Join(mountPath, "roles/default")
	extensions := map[string]string{
		"permit-pty": "",
	}
	defaultRole := &SSHRole{
		AllowUserCertificates: true,
		AllowedUsers:          "*",
		DefaultExtensions:     extensions,
		AllowedExtenstion:     "permit-pty,permit-port-forwarding,permit-user-rc,permit-X11-forwarding,permit-agent-forwarding",
		KeyType:               "ca",
		DefaultUser:           "core",
		TTL:                   "30m",
		MaxTTL:                "4h",
	}
	err = c.writeOp(defaultRolePath, defaultRole, nil, false)
	if err != nil {
		return nil, err
	}
	return &SSH{
		c:    c,
		path: mountPath,
	}, nil
}

type SSHKeyOutput struct {
	PublicKey string `mapstructure:"public_key"`
}

func (s *SSH) GetPublicKey() (string, error) {
	publicKeyPath := path.Join(s.path, "config/ca")
	key := &SSHKeyOutput{}
	err := s.c.readOp(publicKeyPath, key, false)
	if err != nil {
		return "", err
	}
	return key.PublicKey, nil
}
