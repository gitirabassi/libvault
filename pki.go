package libvault

import (
	"net/url"
	"path"

	"github.com/hashicorp/vault/api"
)

const (
	tenYears   = "87600h"
	oneYear    = "8760h"
	ninetyDays = "2160h"
)

// PKI identifies a new PKI (one PKI with CA)
type PKI struct {
	c    *Client
	path string
}

// Certificate is the representation of a certificate as coming out of vault
type Certificate struct {
	Certificate    string   `mapstructure:"certificate"`
	PrivateKey     string   `mapstructure:"private_key"`
	SerialNumber   string   `mapstructure:"serial_number"`
	PrivateKeyType string   `mapstructure:"private_key_type"`
	IssuingCA      string   `mapstructure:"issuing_ca"`
	CaChain        []string `mapstructure:"ca_chain"`
	Expiration     string   `mapstructure:"expiration"`
}

// CertificateRequest is used to
type CertificateRequest struct {
	CommonName        string `mapstructure:"common_name"`
	IPs               string `mapstructure:"ip_sans"`
	AlternativesNames string `mapstructure:"alt_names"`
	TTL               string `mapstructure:"ttl"`
	Format            string `mapstructure:"pem"`
	PrivateKeyFormat  string `mapstructure:"der"`
}

// PKIUrls is used to configure the CA defaults
type PKIUrls struct {
	IssuingCertificates  string `mapstructure:"issuing_certificates"`
	CRLDistributionPoint string `mapstructure:"crl_distribution_points"`
}

// CRLConfiguration is used to configure the CA CRL configurations
type CRLConfiguration struct {
	Expiry  string `mapstructure:"expiry"`
	Disable string `mapstructure:"disable"`
}

// PKIConfig represents the configuration of a CA: Distinguished name and key specifications
type PKIConfig struct {
	CommonName       string `mapstructure:"common_name"`
	Organization     string `mapstructure:"organization"`
	OU               string `mapstructure:"ou"`
	StreetAddress    string `mapstructure:"street_address"`
	Locality         string `mapstructure:"locality"`
	Province         string `mapstructure:"province"`
	PostalCode       string `mapstructure:"postal_code"`
	Country          string `mapstructure:"country"`
	TTL              string `mapstructure:"ttl"`
	PrivateKeyFormat string `mapstructure:"private_key_format"`
	Format           string `mapstructure:"format"`
	KeyType          string `mapstructure:"key_type"`
	KeyBits          string `mapstructure:"key_bits"`
}

// PKI creates a PKI backend ready to use
func (c *Client) PKI(mountPath string, createIfDoesntExist bool) (*PKI, error) {
	mountOptions := &api.MountInput{
		Type:        "pki",
		Description: defaultMountDescription,
		Config: api.MountConfigInput{
			MaxLeaseTTL:     tenYears,
			DefaultLeaseTTL: tenYears,
		},
	}
	err := c.mount(mountPath, mountOptions, createIfDoesntExist)
	if err != nil {
		return nil, err
	}
	// Configuring the PKI secret Backend URLS
	urlsPath := path.Join(mountPath, "config/urls")
	caURL, err := url.Parse(c.GetAPIClient().Address())
	if err != nil {
		return nil, err
	}
	caURL.Path = path.Join(caURL.Path, "v1", mountPath, "ca")
	crlURL, err := url.Parse(c.GetAPIClient().Address())
	if err != nil {
		return nil, err
	}
	crlURL.Path = path.Join(crlURL.Path, "v1", mountPath, "crl")
	urls := &PKIUrls{
		IssuingCertificates:  caURL.String(),
		CRLDistributionPoint: crlURL.String(),
	}
	err = c.writeOp(urlsPath, urls, nil, false)
	if err != nil {
		return nil, err
	}
	// Configuring the PKI secret backend CRLs
	crlPath := path.Join(mountPath, "config/crl")
	crlConf := &CRLConfiguration{
		Expiry:  "48h",
		Disable: "false",
	}
	err = c.writeOp(crlPath, crlConf, nil, false)
	if err != nil {
		return nil, err
	}
	return &PKI{
		c:    c,
		path: mountPath,
	}, nil
}

func (p *PKI) RootExported(conf *PKIConfig) (key string, certificate string, err error) {
	if conf.TTL == "" {
		conf.TTL = tenYears
	}
	if conf.KeyType == "" {
		conf.KeyType = "rsa"
	}
	if conf.KeyBits == "" {
		conf.KeyBits = "4096"
	}
	if conf.PrivateKeyFormat == "" {
		conf.PrivateKeyFormat = "der"
	}
	if conf.Format == "" {
		conf.Format = "pem"
	}
	genRootPath := path.Join(p.path, "root/generate/exported")
	outCa := &Certificate{}
	err = p.c.writeOp(genRootPath, conf, outCa, false)
	if err != nil {
		return "", "", err
	}
	return outCa.PrivateKey, outCa.Certificate, nil
}

// Root creates root CA
func (p *PKI) Root(conf *PKIConfig) error {
	if conf.TTL == "" {
		conf.TTL = tenYears
	}
	if conf.KeyType == "" {
		conf.KeyType = "rsa"
	}
	if conf.KeyBits == "" {
		conf.KeyBits = "4096"
	}
	if conf.PrivateKeyFormat == "" {
		conf.PrivateKeyFormat = "der"
	}
	if conf.Format == "" {
		conf.Format = "pem"
	}
	genRootPath := path.Join(p.path, "root/generate/internal")
	err := p.c.writeOp(genRootPath, conf, nil, false)
	if err != nil {
		return err
	}
	return nil
}

// CreateDefaultRoles creates common used roles (server, client, peer)
func (p *PKI) CreateDefaultRoles(allowedDomains ...string) error {
	peerRole := DefaultRoleConfiguration(allowedDomains...)
	peerRole.ServerFlag = true
	peerRole.ClientFlag = true
	peerRole.ExtKeyUsage = []string{"ClientAuth", "ServerAuth"}
	err := p.CreateRole("peer", peerRole)
	if err != nil {
		return err
	}
	clientRole := DefaultRoleConfiguration(allowedDomains...)
	clientRole.ServerFlag = false
	clientRole.ClientFlag = true
	clientRole.ExtKeyUsage = []string{"ServerAuth"}
	err = p.CreateRole("client", clientRole)
	if err != nil {
		return err
	}
	serverRole := DefaultRoleConfiguration(allowedDomains...)
	serverRole.ServerFlag = true
	serverRole.ClientFlag = false
	serverRole.ExtKeyUsage = []string{"ClientAuth"}
	err = p.CreateRole("server", serverRole)
	if err != nil {
		return err
	}
	return nil
}

// CreateRole adds a role to a given PKI secret backend
func (p *PKI) CreateRole(name string, conf *PKIRole) error {
	newRolePath := path.Join(p.path, "roles", name)
	err := p.c.writeOp(newRolePath, conf, nil, false)
	if err != nil {
		return err
	}
	return nil
}

// DefaultRoleConfiguration creates sane default for configurations
func DefaultRoleConfiguration(allowesDomains ...string) *PKIRole {
	return &PKIRole{
		TTL:                 ninetyDays,
		MaxTTL:              oneYear,
		CodeSigningFlag:     false,
		EmailProtectionFlag: false,
		KeyUsage:            []string{"DigitalSignature", "KeyEncipherment"},
		AllowLocalhost:      false,
		AllowGlobDomains:    false,
		AllowIPSans:         true,
		RequireCN:           true,
		NonCA:               true,
		AllowAnyName:        false,
		AllowSubdomains:     false,
		AllowBareDomains:    true,
		AllowedDomains:      allowesDomains,
		GenerateLease:       true,
		EnforceHostnames:    true,
	}
}

// PKIRole is used to create and manage roles in vault PKI backend
type PKIRole struct {
	TTL                 string   `mapstructure:"ttl"`
	MaxTTL              string   `mapstructure:"max_ttl"`
	CodeSigningFlag     bool     `mapstructure:"code_signing_flag"`
	EmailProtectionFlag bool     `mapstructure:"email_protection_flag"`
	KeyUsage            []string `mapstructure:"key_usage"`
	AllowLocalhost      bool     `mapstructure:"allow_localhost"`
	AllowGlobDomains    bool     `mapstructure:"allow_glob_domains"`
	AllowIPSans         bool     `mapstructure:"allow_ip_sans"`
	RequireCN           bool     `mapstructure:"require_cn"`
	NonCA               bool     `mapstructure:"basic_constraints_valid_for_non_ca"`
	AllowAnyName        bool     `mapstructure:"allow_any_name"`
	AllowSubdomains     bool     `mapstructure:"allow_subdomains"`
	AllowBareDomains    bool     `mapstructure:"allow_bare_domains"`
	AllowedDomains      []string `mapstructure:"allowed_domains"`
	ServerFlag          bool     `mapstructure:"server_flag"`
	ClientFlag          bool     `mapstructure:"client_flag"`
	ExtKeyUsage         []string `mapstructure:"ext_key_usage"`
	GenerateLease       bool     `mapstructure:"generate_lease"`
	OU                  string   `mapstructure:"ou"`
	Organization        string   `mapstructure:"organization"`
	EnforceHostnames    bool     `mapstructure:"enforce_hostnames"`
}

// func (c *Certificate) DecodePEM() (crypto.Signer, crypto.PublicKey, error) {

// }

// // GetCertificate gets a new certificates from a given provider
// func (p *PKI) GetCertificate(role, CN, ttl string, SANs, IPs []string) (*Certificate, error) {
// 	// Creating certificate issuing request
// 	crs := &CertificateRequest{
// 		CommonName:       CN,
// 		Format:           "pem",
// 		PrivateKeyFormat: "der",
// 	}
// 	issuePath := filepath.Join(c.backendPath, "issue", role)
// 	if IPs != nil {
// 		crs.IPs = strings.Join(IPs, ",")
// 	}
// 	if SANs != nil {
// 		crs.AlternativesNames = strings.Join(SANs, ",")
// 	}
// 	if ttl != "-1" {
// 		crs.TTL = ttl
// 	}
// 	rawCert, err := c.Logical().Write(issuePath, issuePayload)
// 	if err != nil {
// 		return nil, err
// 	}
// 	cert := &Certificate{}
// 	err = UnmarshalSecret(rawCert, cert)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return cert, nil
// }

// // Persist writes the certificate to disk
// func (c *Certificate) Persist(baseDir, name string, ca bool) error {
// 	return nil
// }
