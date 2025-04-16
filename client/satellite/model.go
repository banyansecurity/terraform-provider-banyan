package satellite

type SatelliteStatus string

const (
	Unknown          SatelliteStatus = "Unknown"
	Pending          SatelliteStatus = "Pending"
	Healthy          SatelliteStatus = "Healthy"
	PartiallyHealthy SatelliteStatus = "PartiallyHealthy"
	UnHealthy        SatelliteStatus = "Unhealthy"
	InActive         SatelliteStatus = "Inactive"
	Terminated       SatelliteStatus = "Terminated"
)

type SatelliteTunnelResponse struct {
	Data SatelliteTunnelConfig `json:"data"`
}

const (
	DefaultName      = "default-connector"
	ConnectorNameKey = "connector"
)

type SatelliteTunnelConfig struct {
	ID                  string       `json:"id"`
	OrgID               string       `json:"org_id"`
	Name                string       `json:"name"`
	DisplayName         string       `json:"display_name"`
	TunnelIPAddress     string       `json:"tunnel_ip_address"`
	Keepalive           int64        `json:"keepalive"`
	Status              string       `json:"status,omitempty"`
	WireguardPublicKey  string       `json:"wireguard_public_key"`
	WireguardPrivateKey string       `json:"wireguard_private_key,omitempty"`
	CIDRs               []string     `json:"cidrs"`
	AccessTiers         []AccessTier `json:"access_tiers"`
	CreatedAt           int64        `json:"created_at,omitempty"`
	UpdatedAt           int64        `json:"updated_at,omitempty"`
	APIKeyID            string       `json:"api_key_id,omitempty"`
	ConnectorVersion    string       `json:"connector_version,omitempty"`
	HostInfo            *HostInfo    `json:"host_info,omitempty"`
	LastStatusUpdatedAt int64        `json:"-"`
	SSHCAPublicKey      string       `json:"ssh_ca_public_key,omitempty"`
	CreatedBy           string       `json:"created_by"`
	UpdatedBy           string       `json:"updated_by"`
	Spec                string       `json:"spec"`
	IpTables            string       `json:"ip_tables,omitempty"`
	Domains             []string     `json:"domains"`
	Description         string       `json:"description"`
}

type AccessTier struct {
	SatelliteTunnelPeerID string `json:"satellite_tunnel_peer_id"`
	AccessTierID          string `json:"access_tier_id"`
	Healthy               *bool  `json:"healthy,omitempty"`
	WireguardPublicKey    string `json:"wireguard_public_key,omitempty"`
	Endpoint              string `json:"endpoint,omitempty"`
	AllowedIPs            string `json:"allowed_ips,omitempty"`
	AccessTierName        string `json:"access_tier_name,omitempty"`
}

type SatellitePeerStatus struct {
	AccessTierID       string `json:"access_tier_id"`
	Healthy            *bool  `json:"healthy"`
	WireguardPublicKey string `json:"wireguard_public_key"`
	Endpoint           string `json:"endpoint"`
	AllowedIPs         string `json:"allowed_ips"`
	LatestHandshake    string `json:"latest_handshake"`
	Transfer           string `json:"transfer"`
}

type HostInfo struct {
	Name        string   `json:"name"`
	IPAddresses []string `json:"ip_addresses"`
}

type PeersStatus struct {
	ConnectorVersion *string               `json:"connector_version,omitempty"`
	HostInfo         *HostInfo             `json:"host_info,omitempty"`
	Peers            []SatellitePeerStatus `json:"peers"`
}

func (s *SatelliteTunnelConfig) Sanitize() {
	s.WireguardPrivateKey = ""
}

type Info struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api_version"`
	Type       string `json:"type"` //attribute
	Metadata   `json:"metadata"`
	Spec       `json:"spec"`
}

type Metadata struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

type Spec struct {
	APIKeyID        string           `json:"api_key_id"`
	Keepalive       int64            `json:"keepalive"`
	CIDRs           []string         `json:"cidrs"`
	PeerAccessTiers []PeerAccessTier `json:"peer_access_tiers"`
	DisableSnat     bool             `json:"disable_snat"`
	Domains         []string         `json:"domains,omitempty"`
	Deployment      *Deployment      `json:"deployment,omitempty"`

	ExtendedNetworkAccess bool `json:"extended_network_access"`
}

type Deployment struct {
	Platform string `json:"platform"` // Windows, Linux, sonicOS, other
	Method   string `json:"method"`   // app, tar, docker, firmware, terraform, other
}

type PeerAccessTier struct {
	Cluster     string   `json:"cluster"`
	AccessTiers []string `json:"access_tiers"`
}
