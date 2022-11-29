package accesstier

//TunnelConfig used to send tunnel config from restapi to banyan app.
type TunnelConfig struct {
	LocalIPaddress string                        `json:"local_ip_address"`
	AccessTiers    []EnduserFacingAccessTierInfo `json:"access_tiers"`
}

//EnduserFacingAccessTierInfo used to send to send access tier tunnel config data from restapi to banyan app.
type EnduserFacingAccessTierInfo struct {
	ID                 string   `json:"id"`
	OrgID              string   `json:"org_id"`
	AccessTierID       string   `json:"access_tier_id"`
	DNSSearchDomains   string   `json:"dns_search_domains"`
	UDPPortNumber      int64    `json:"udp_port_number"`
	TunnelIPAddress    string   `json:"tunnel_ip_address"`
	CIDRs              []string `json:"cidrs"`
	WireguardPublicKey string   `json:"wireguard_public_key"`
	Keepalive          int64    `json:"keepalive"`
	Domains            []string `json:"domains"`
	DNSEnabled         bool     `json:"dns_enabled"`
	CName              string   `json:"cname"`
	SiteName           string   `json:"site_name"`
}

// Below structures used between banyan wireguard service and banyan app

// End user wireguard client specific configuration
type EndUserClientConfig struct {
	WireguardPrivateKey string `json:"wireguard_private_key"`
	LocalIpAddress      string `json:"local_ip_address"`
}

// End user complete service tunnel configuration
type EndUserServiceTunnelConfig struct {
	EndUserConfig   EndUserClientConfig           `json:"enduser_config"`
	AccessTiers     []EnduserFacingAccessTierInfo `json:"access_tiers"`
	ServiceTunnelID string                        `json:"service_tunnel_id"`
	ExpiresOn       int64                         `json:"expires_on"`
}
