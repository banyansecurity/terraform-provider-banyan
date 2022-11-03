package accesstier

type CASignInfo struct {
	ID      string // unique id for each req/resp
	Profile string // signing profile for generating various types of certificates
	ReqPEM  string // PEM encoded request to sign
	CertPEM string // SignedCert

	UserPrincipalName string   `json:"UserPrincipalName,omitempty"` // UPN SAN extension (an email address, or empty string)
	UserRoles         []string `json:"user_roles,omitempty"`
	SSHCert           string   `json:"ssh_cert,omitempty"`
	SSHCAPublicKey    string   `json:"ssh_ca_public_key,omitempty"`
}
