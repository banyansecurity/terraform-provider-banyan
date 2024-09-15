package servicetunnel

import "github.com/banyansecurity/terraform-banyan-provider/client/dns"

type GetPolicyAttachmentInfo struct {
	ID             string `json:"id"`
	PolicyID       string `json:"policy_id"`
	PolicyName     string `json:"policy_name"`
	AttachedToID   string `json:"attached_to_id"`
	AttachedToType string `json:"attached_to_type"`
	AttachedBy     string `json:"attached_by"`
	AttachedAt     int64  `json:"Attached_at"`
	Enabled        string `json:"enabled"`
}
type PolicyAttachmentInfo struct {
	ID              string `json:"id"`
	PolicyID        string `json:"policy_id"`
	PolicyVersion   int64  `json:"policy_version"`
	ServiceTunnelID string `json:"service_tunnel_id"`
	AttachedBy      string `json:"attached_by"`
	AttachedAt      int64  `json:"Attached_at"`
	Enabled         bool   `json:"enabled"`
}

type PolicyAttachmentPost struct {
	PolicyID string `json:"policy_id"`
	Enabled  bool   `json:"enabled"` //true/false: true => Enforced; false => Permissive mode
}

type PolicyResponse struct {
	RequestId        string               `json:"request_id"`
	ErrorCode        int                  `json:"error_code"`
	ErrorDescription string               `json:"error_description"`
	Data             PolicyAttachmentInfo `json:"data"`
}

type GetPolicyResponse struct {
	RequestId        string                  `json:"request_id"`
	ErrorCode        int                     `json:"error_code"`
	ErrorDescription string                  `json:"error_description"`
	Data             GetPolicyAttachmentInfo `json:"data"`
}

// ServiceTunnelInfo used to send data to shield over websocket from restapi
type ServiceTunnelInfo struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	Name         string `json:"name"`
	FriendlyName string `json:"friendly_name"`
	Description  string `json:"description"`
	Enabled      bool   `json:"enabled"`
	Spec         Info   `json:"spec"`
	CreatedAt    int64  `json:"created_at"`
	CreatedBy    string `json:"created_by"`
	UpdatedAt    int64  `json:"updated_at"`
	UpdatedBy    string `json:"updated_by"`

	ActiveConnectionsCount int64 `json:"active_connections_count"`
}

// Contains the spec string from the api response
type ServiceTunnelInfoResponse struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	Name         string `json:"name"`
	FriendlyName string `json:"friendly_name"`
	Description  string `json:"description"`
	Enabled      bool   `json:"enabled"`
	Spec         string `json:"spec"`
	CreatedAt    int64  `json:"created_at"`
	CreatedBy    string `json:"created_by"`
	UpdatedAt    int64  `json:"updated_at"`
	UpdatedBy    string `json:"updated_by"`
}

// Info represents the specification of a service tunnel "service".
type Info struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api_version"`
	Type       string `json:"type"` //attribute
	Metadata   `json:"metadata"`
	Spec       `json:"spec"`
}

// Metadata represents the metadata stanza of an Info.
type Metadata struct {
	Name         string `json:"name,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	Description  string `json:"description,omitempty"`
	Autorun      bool   `json:"autorun"`
	LockAutoRun  bool   `json:"lock_autorun"`
	Tags         Tags   `json:"tags"`
}

// Tags represents the metadata tags
type Tags struct {
	Icon            *string `json:"icon,omitempty"`
	DescriptionLink *string `json:"description_link,omitempty"`
}

// Spec represents the attributes stanza of a Info.
type Spec struct {
	PeerAccessTiers []PeerAccessTier        `json:"peer_access_tiers"`
	NameResolution  *dns.NameResolutionInfo `json:"name_resolution,omitempty"`
}

type PeerAccessTier struct {
	Cluster     string   `json:"cluster"`
	AccessTiers []string `json:"access_tiers"`
	Connectors  []string `json:"connectors,omitempty"`

	PublicCIDRs   *IncludeExclude `json:"public_cidrs,omitempty"`
	PublicDomains *IncludeExclude `json:"public_domains,omitempty"`
	Applications  *IncludeExclude `json:"applications,omitempty"`

	AccessTierGroup string `json:"access_tier_group"`
}

type IncludeExclude struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type Response struct {
	RequestId        string                    `json:"request_id"`
	ErrorCode        int                       `json:"error_code"`
	ErrorDescription string                    `json:"error_description"`
	Data             ServiceTunnelInfoResponse `json:"data"`
	Count            int                       `json:"count"`
}
