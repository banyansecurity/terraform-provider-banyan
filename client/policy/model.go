package policy

type Spec struct {
	Access    []Access  `json:"access"`
	Exception Exception `json:"exception"`
	Options   Options   `json:"options"`
}
type Options struct {
	DisableTLSClientAuthentication bool   `json:"disable_tls_client_authentication"`
	L7Protocol                     string `json:"l7_protocol"`
}

type Exception struct {
	SourceAddress []string `json:"src_addr"`
}

type Access struct {
	Roles []string `json:"roles"`
	Rules Rules    `json:"rules"`
}

type Rules struct {
	Conditions Conditions `json:"conditions"`
	L7Access   []L7Access `json:"l7_access"`
}

type L7Access struct {
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

type Conditions struct {
	TrustLevel string `json:"trust_level"`
}

type CreatePolicy struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Type       string   `json:"type"`
	Spec       Spec     `json:"spec"`
}

type Metadata struct {
	Description string `json:"description"`
	Name        string `json:"name"`
	Tags        Tags   `json:"tags"`
}

type Tags struct {
	Template string `json:"template"`
}

type GetPolicy struct {
	CreatedAt          int    `json:"CreatedAt"`
	CreatedBy          string `json:"CreatedBy"`
	DeletedAt          int    `json:"DeletedAt"`
	DeletedBy          string `json:"DeletedBy"`
	Description        string `json:"Description"`
	LastUpdatedAt      int    `json:"LastUpdatedAt"`
	LastUpdatedBy      string `json:"LastUpdatedBy"`
	ID                 string `json:"PolicyID"`
	Name               string `json:"PolicyName"`
	Spec               string `json:"PolicySpec"`
	Version            int    `json:"PolicyVersion"`
	UnmarshalledPolicy CreatePolicy
}
