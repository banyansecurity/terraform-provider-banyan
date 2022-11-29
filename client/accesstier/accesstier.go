package accesstier

type AccessTierStatus string

type HostInfo struct {
	Hostname string
	IPs      []string
}

type NetagentHostInfo struct {
	HostInfo
	Version        string            // com.banyanops.netagent.version
	Visibility     bool              // com.banyanops.command =~ /visibilityOnly=false/
	CIDRs          string            // com.banyanops.netagent.cidrs
	HostTags       map[string]string // com.banyanops.hosttag.*
	Uname          string            // com.banyanops.netagent.uname
	SiteName       string            //com.banyanops.hosttag.site_name
	ClusterID      string
	LastActivityAt string
	CreatedAt      string
	Status         string
	IpTables       string
}

type ATResponse struct {
	RequestId        string         `json:"request_id"`
	ErrorCode        int            `json:"error_code"`
	ErrorDescription string         `json:"error_description"`
	Data             AccessTierInfo `json:"data"`
	Count            int            `json:"count"`
}

// AccessTierPostBody represents the specification of a service populated by json.Unmarshal.
type AccessTierPostBody struct {
	Kind       string         `json:"kind" toml:"kind"`
	APIVersion string         `json:"api_version" toml:"api_version"`
	Type       string         `json:"type" toml:"type"` //attribute
	Metadata   Metadata       `json:"metadata" toml:"metadata"`
	Spec       AccessTierPost `json:"spec" toml:"spec"`
}

type AccessTierPost struct {
	Name             string                    `json:"name"`
	Address          string                    `json:"address"`
	Domains          []string                  `json:"domains"`
	TunnelSatellite  *AccessTierTunnelInfoPost `json:"tunnel_satellite,omitempty"`
	TunnelEnduser    *AccessTierTunnelInfoPost `json:"tunnel_enduser,omitempty"`
	ClusterName      string                    `json:"cluster_name"`
	DisableSnat      bool                      `json:"disable_snat"`
	SrcNATCIDRRange  string                    `json:"src_nat_cidr_range,omitempty"`
	Description      string                    `json:"description"`
	ApiKeyId         string                    `json:"api_key_id"`
	DeploymentMethod string                    `json:"deployment_method"`
}

type AccessTierInfo struct {
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	Address         string                `json:"address"`
	Domains         []string              `json:"domains"`
	Status          string                `json:"status"`
	Netagents       []NetagentHostInfo    `json:"netagents"`
	TunnelSatellite *AccessTierTunnelInfo `json:"tunnel_satellite,omitempty"`
	TunnelEnduser   *AccessTierTunnelInfo `json:"tunnel_enduser,omitempty"`
	DisableSnat     bool                  `json:"disable_snat"`
	SrcNATCIDRRange string                `json:"src_nat_cidr_range,omitempty"`
	CreatedAt       int64                 `json:"created_at"`
	CreatedBy       string                `json:"created_by"`
	UpdatedAt       int64                 `json:"updated_at"`
	UpdatedBy       string                `json:"updated_by"`
	ClusterName     string                `json:"cluster_name"`

	// Don't surface local config when marshalling JSON
	LocalConfig      string `json:"-"`
	ShieldAddress    string `json:"shield_address"`
	Spec             string `json:"spec,omitempty"`
	APIKeyID         string `json:"api_key_id"`
	Description      string `json:"description"`
	DeploymentMethod string `json:"deployment_method,omitempty"`
}

type AccessTierServiceInfoDetails struct {
	OrgID        string `json:"org_id"`
	AccessTierID string `json:"access_tier_id"`
	ServiceID    string `json:"service_id"`
	ServiceType  string `json:"service_type"`
	CreatedAt    int64  `json:"created_at"`
}

type AccessTierComplete struct {
	AccessTierInfo
	AccessTierLocalConfig
}

type Metadata struct {
	Name         string `json:"name,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	Description  string `json:"description,omitempty"`
	Tags         Tags   `json:"tags"`
}

type Tags struct {
	Template        *string `json:"template,omitempty"`
	UserFacing      *string `json:"user_facing,omitempty"`
	Icon            *string `json:"icon,omitempty"`
	DescriptionLink *string `json:"description_link,omitempty"`
}
