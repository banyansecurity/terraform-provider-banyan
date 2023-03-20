package policy

import "strings"

type PolicyMode string

const (
	ENFORCING  PolicyMode = "Enforcing"
	PERMISSIVE PolicyMode = "Permissive"
)

const (
	ServiceTypeTCP = "TCP"
	ServiceTypeWeb = "WEB"
	ProtocolHTTPS  = "HTTPS"
	ProtocolHTTP   = "HTTP"
)

// Object represents the specification of a service populated by json.Unmarshal.
type Object struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Type       string `json:"type"`
	Metadata   `json:"metadata"`
	Spec       `json:"spec"`
}

// Metadata represents the metadata stanza of an Object.
type Metadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Tags        Tags   `json:"tags"`
}

// Tags represents the metadata tags
type Tags struct {
	Template string `json:"template"`
}

// Spec defines the policy details.
type Spec struct {
	Options   `json:"options"`
	Access    []Access `json:"access"`
	Exception `json:"exception"`
	// Egress    `json:"egress"`
}

// Options defines general parameters that apply to all access groups.
type Options struct {
	// DisableTLSClientAuthentication=true prevents the service from asking for a client TLS cert.
	DisableTLSClientAuthentication bool `json:"disable_tls_client_authentication"`
	// L7Protocol specifies the application-level protocol: "http", "kafka", or empty string.
	// If L7Protocol is not empty, then all Access rules must have L7Access entries.
	L7Protocol string `json:"l7_protocol"`
	//MixedUsersAndWorkloads=false selects either Workload or User.
	//If MixedUsersAndWorkloads=true, the mixed mode is selected and both classes of connections are supported
	MixedUsersAndWorkloads bool `json:"mixed_users_and_workloads,omitempty"`
}

// Access describes the access rights for a set of roles.
type Access struct {
	// Roles is a list of Role names to include .
	Roles []string `json:"roles"`
	// Rules lists the access rights given to principals/subjects that have any of the corresponding Roles.
	Rules `json:"rules"`
}

// Rules lists a set of access rights, along with any required conditions that must be satisfied
// for the access rights to be enabled.
type Rules struct {
	Comment    string     `json:"_comment,omitempty"`
	L7Access   []L7Access `json:"l7_access"`
	L4Access   *L4Access  `json:"l4_access,omitempty"`
	Conditions `json:"conditions"`
}

// Conditions specifies conditions that must be satisfied in order for access rights to be enabled.
type Conditions struct {
	// StartTime, if not empty, specifes the start time in RFC3339 format (https://tools.ietf.org/html/rfc3339).
	StartTime string `json:"start_time,omitempty"`
	// EndTime, if not empty, specifes the end time in RFC3339 format (https://tools.ietf.org/html/rfc3339).
	EndTime string `json:"end_time,omitempty"`
	// TrustLevel specifies the minimum trust level of the access ("Low", "Medium", "High").
	TrustLevel string `json:"trust_level,omitempty"`
}

// L7Access specifies a set of access rights to application level (OSI Layer-7) resources.
type L7Access struct {
	// Resources are a list of application level resources.
	// Each resource can have wildcard prefix or suffix, or both.
	// A resource can be prefixed with "!", meaning DENY.
	// Any DENY rule overrides any other rule that would allow the access.
	// HTTP resources require a leading "/"
	Resources []string `json:"resources"`
	// Actions are a list of application-level actions: "READ", "WRITE", "CREATE", "UPDATE", "*".
	Actions []string `json:"actions"`
	// [Deprecated] accept either action or actions, for backward compatibility.
	Action []string `json:"action,omitempty"`
}

// L4Access specifies a set of access rights to network level (OSI Layer-4) resources.
type L4Access struct {
	Deny  []L4Rule `json:"deny,omitempty"`
	Allow []L4Rule `json:"allow,omitempty"`
}

type L4Rule struct {
	CIDRs     []string `json:"cidrs,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
	Ports     []string `json:"ports,omitempty"`
	FQDNs     []string `json:"fqdns,omitempty"`
}

// Exception describes exceptional cases that bypass regular policy enforcement.
type Exception struct {
	// SrcAddr is a list of CIDRs describing source addresses that do not need to use TLS to gain access.
	SrcAddr []string `json:"src_addr"`
	// [Deprecated] TLSSrcAddr is a list of CIDRs describing source addresses that must use TLS but must
	// not be asked to supply a client certificate in the TLS handshake.
	TLSSrcAddr []string `json:"tls_src_addr,omitempty"`
}

// type Egress struct {
// 	DestAddr []string `json:"dest_addr"`
// }

const (
	// L7 Protocols
	L7_PROTOCOL_HTTP  string = "http"
	L7_PROTOCOL_KAFKA string = "kafka"
	L7_PROTOCOL_MYSQL string = "mysql"
)

const (
	// L7 Access actions
	L7_ACCESS_ACTION_CREATE string = "create"
	L7_ACCESS_ACTION_WRITE  string = "write"
	L7_ACCESS_ACTION_READ   string = "read"
	L7_ACCESS_ACTION_UPDATE string = "update"
	L7_ACCESS_ACTION_DELETE string = "delete"
	L7_ACCESS_ACTION_ALL    string = "*"
)

func (policySpec *Object) IsWeb() bool {
	if strings.ToUpper(policySpec.L7Protocol) == ProtocolHTTP && policySpec.DisableTLSClientAuthentication {
		return true
	}

	return false
}

func (policySpec *Object) IsTCP() bool {
	if strings.ToUpper(policySpec.L7Protocol) == "" && !policySpec.DisableTLSClientAuthentication {
		return true
	}

	return false
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
	UnmarshalledPolicy Object
}
