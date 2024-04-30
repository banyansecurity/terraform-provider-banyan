package accesstiergroup

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
)

type AccessTierGroupInfo struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	OrgID            string `json:"org_id"`
	Description      string `json:"description"`
	TunnelConfigID   string `json:"tunnel_config_id"`
	AdvancedSettings string `json:"advanced_settings"`
	ClusterName      string `json:"cluster_name"`
	CreatedAt        int64  `json:"created_at"`
	UpdatedAt        int64  `json:"updated_at"`
}

type AccessTierGroupPost struct {
	ID               string                               `json:"id"`
	Name             string                               `json:"name"`
	OrgID            string                               `json:"org_id"`
	Description      string                               `json:"description"`
	SharedFQDN       string                               `json:"shared_fqdn"`
	TunnelConfig     *accesstier.AccessTierTunnelInfoPost `json:"tunnel_enduser"`
	AdvancedSettings accesstier.AccessTierLocalConfig     `json:"advanced_settings"`
	ClusterName      string                               `json:"cluster_name"`
	CreatedAt        int64                                `json:"created_at"`
	UpdatedAt        int64                                `json:"updated_at"`
}

type AccessTierGroupResponse struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	OrgID            string           `json:"org_id"`
	Description      string           `json:"description"`
	AdvancedSettings string           `json:"advanced_settings"`
	AccessTierIDs    []string         `json:"access_tier_ids"`
	ClusterName      string           `json:"cluster_name"`
	CreatedAt        int64            `json:"created_at"`
	UpdatedAt        int64            `json:"updated_at"`
	TunnelConfig     TunnelConfigInfo `json:"tunnel_enduser"`
}

type TunnelConfigInfo struct {
	ID                  string `json:"id"`
	OrgID               string `json:"org_id"`
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

type ATGResponse struct {
	RequestId        string                  `json:"request_id"`
	ErrorCode        int                     `json:"error_code"`
	ErrorDescription string                  `json:"error_description"`
	Data             AccessTierGroupResponse `json:"data"`
}

type AccessTierList struct {
	AccessTierIDs []string `json:"access_tier_ids"`
}
