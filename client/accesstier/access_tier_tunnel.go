package accesstier

const (
	SatelliteTunnelPeerType     = "satellite"
	EnduserDeviceTunnelPeerType = "enduser_device"

	DisallowedCIDRRange = "0.0.0.0/0"
)

//AccessTierTunnelInfo used to send access tier tunnel config data from restapi to shield over web socket and in curd operation
//in restapi.
type AccessTierTunnelInfo struct {
	ID                  string `json:"id"`
	OrgID               string `json:"org_id"`
	AccessTierID        string `json:"access_tier_id"`
	TunnelPeerType      string `json:"tunnel_peer_type"`
	DNSSearchDomains    string `json:"dns_search_domains"`
	UDPPortNumber       int64  `json:"udp_port_number"`
	TunnelIPAddress     string `json:"tunnel_ip_address"`
	WireguardPublicKey  string `json:"wireguard_public_key"`
	WireguardPrivateKey string `json:"wireguard_private_key,omitempty"`
	DNSEnabled          bool   `json:"dns_enabled"`
	Keepalive           int64  `json:"keepalive"`
	CreatedAt           int64  `json:"created_at"`
	UpdatedAt           int64  `json:"updated_at"`
	SharedFQDN          string `json:"shared_fqdn,omitempty"`

	CIDRs   []string `json:"cidrs"`
	Domains []string `json:"domains"`

	ClientCIDRRange string `json:"client_cidr_range"`
}

type AccessTierTunnelInfoPost struct {
	DNSSearchDomains string   `json:"dns_search_domains,omitempty"`
	UDPPortNumber    int      `json:"udp_port_number,omitempty"`
	TunnelIPAddress  string   `json:"tunnel_ip_address,omitempty"`
	DNSEnabled       bool     `json:"dns_enabled,omitempty"`
	CIDRs            []string `json:"cidrs,omitempty"`
	Domains          []string `json:"domains,omitempty"`
}

func (a *AccessTierTunnelInfo) Sanitize() {
	a.WireguardPrivateKey = ""
}
