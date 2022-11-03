package accesstier

type PolicyAttachmentInfo struct {
	ID              string `json:"id"`
	PolicyID        string `json:"policy_id"`
	PolicyVersion   int    `json:"policy_version"`
	ServiceTunnelID string `json:"service_tunnel_id"`
	AttachedBy      string `json:"attached_by"`
	AttachedAt      int64  `json:"Attached_at"`
	Enabled         bool   `json:"enabled"` //true/false: true => Enforced; false => Permissive mode
}

//ServiceTunnelInfo used to send data to shield over websocket from restapi
type ServiceTunnelInfo struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	Name         string `json:"name"`
	FriendlyName string `json:"friendly_name"`
	Description  string `json:"description"`
	Enabled      bool   `json:"enabled"`
	Spec         Spec   `json:"spec"`
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
	Tags         Tags   `json:"tags"`
}

// Tags represents the metadata tags
type Tags struct {
	Template        *string `json:"template,omitempty"`
	UserFacing      *string `json:"user_facing,omitempty"`
	Icon            *string `json:"icon,omitempty"`
	DescriptionLink *string `json:"description_link,omitempty"`
}

// Spec represents the attributes stanza of a Info.
type Spec struct {
	PeerAccessTiers []PeerAccessTier `json:"peer_access_tiers"`
}

type PeerAccessTier struct {
	Cluster     string   `json:"cluster"`
	AccessTiers []string `json:"access_tiers"`
	Connectors  []string `json:"connectors,omitempty"`
}
