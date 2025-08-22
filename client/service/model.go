package service

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type Service struct {
	restClient *restclient.Client
}

// NewClient returns a new client for interaction with the service resource
func NewClient(restClient *restclient.Client) Client {
	serviceClient := Service{
		restClient: restClient,
	}
	return &serviceClient
}

type Client interface {
	Get(id string) (spec GetServiceSpec, err error)
	Create(spec CreateService) (created GetServiceSpec, err error)
	Update(id string, spec CreateService) (updated GetServiceSpec, err error)
	Delete(id string) (err error)
	DetachPolicy(id string) (err error)
	Disable(id string) (err error)
	Enable(id string) (err error)
	GetPolicyForService(id string) (attachedPolicy policy.GetPolicy, err error)
}

type Services struct {
	Service []Info `toml:"service"`
}

// Info represents the specification of a service populated by json.Unmarshal.
type Info struct {
	Kind       string `json:"kind" toml:"kind"`
	APIVersion string `json:"apiVersion" toml:"apiVersion"`
	Type       string `json:"type" toml:"type"` //attribute
	Metadata   `json:"metadata" toml:"metadata"`
	Spec       `json:"spec" toml:"spec"`
}

// Metadata represents the metadata stanza of an Info.
type Metadata struct {
	Name         string `json:"name" toml:"name"`
	FriendlyName string `json:"friendly_name,omitempty" toml:"friendly_name"`
	Description  string `json:"description" toml:"description"`
	ClusterName  string `json:"cluster" toml:"cluster"`
	Tags         Tags   `json:"tags" toml:"tags"`
	Autorun      bool   `json:"autorun,omitempty" toml:"autorun,omitempty"`
}

// Tags represents the metadata tags
type Tags struct {
	Template          *string   `json:"template,omitempty" toml:"template,omitempty"`
	UserFacing        *string   `json:"user_facing,omitempty" toml:"user_facing,omitempty"`
	Protocol          *string   `json:"protocol,omitempty" toml:"protocol,omitempty"`
	Domain            *string   `json:"domain,omitempty" toml:"domain,omitempty"`
	Port              *string   `json:"port,omitempty" toml:"port,omitempty"`
	Icon              *string   `json:"icon,omitempty" toml:"icon,omitempty"`
	ServiceAppType    *string   `json:"service_app_type,omitempty" toml:"service_app_type,omitempty"`
	EnforcementMode   *string   `json:"enforcement_mode,omitempty" toml:"enforcement_mode,omitempty"`
	SSHServiceType    *string   `json:"ssh_service_type,omitempty" toml:"ssh_service_type,omitempty"`
	WriteSSHConfig    *bool     `json:"write_ssh_config,omitempty" toml:"write_ssh_config,omitempty"`
	BanyanProxyMode   *string   `json:"banyanproxy_mode,omitempty" toml:"banyanproxy_mode,omitempty"`
	AppListenPort     *string   `json:"app_listen_port,omitempty" toml:"app_listen_port,omitempty"`
	AllowUserOverride *bool     `json:"allow_user_override,omitempty" toml:"allow_user_override,omitempty"`
	SSHChainMode      *bool     `json:"ssh_chain_mode,omitempty" toml:"ssh_chain_mode,omitempty"`
	SSHHostDirective  *string   `json:"ssh_host_directive,omitempty" toml:"ssh_host_directive,omitempty"`
	KubeClusterName   *string   `json:"kube_cluster_name,omitempty" toml:"kube_cluster_name,omitempty"`
	KubeCaKey         *string   `json:"kube_ca_key,omitempty" toml:"kube_ca_key,omitempty"`
	DescriptionLink   *string   `json:"description_link,omitempty" toml:"description_link,omitempty"`
	IncludeDomains    *[]string `json:"include_domains,omitempty" toml:"include_domains,omitempty"`

	RDPSettings *[]string `json:"rdp_settings,omitempty" toml:"rdp_settings,omitempty"`

	RegisteredDomainID *string `json:"registered_domain_id,omitempty" toml:"registered_domain_id,omitempty"`
}

// Spec represents the attributes stanza of an Info.
type Spec struct {
	Attributes   `json:"attributes" toml:"attributes"`
	Backend      `json:"backend" toml:"backend"`
	CertSettings `json:"cert_settings" toml:"cert_settings"`
	HTTPSettings `json:"http_settings" toml:"http_settings"`
	ClientCIDRs  []ClientCIDRs `json:"client_cidrs" toml:"client_cidrs"`
	TagSlice     `json:"tags,omitempty" toml:"tags"`
	CorsEnabled  bool `json:"cors_enabled" toml:"cors_enabled"`
}

type Attributes struct {
	TLSSNI            []string            `json:"tls_sni" toml:"tls_sni"`
	FrontendAddresses []FrontendAddress   `json:"frontend_addresses" toml:"frontend_addresses"`
	HostTagSelector   []map[string]string `json:"host_tag_selector" toml:"host_tag_selector"`
	// deprecated: Addresses
	Addresses         []string `json:"addresses,omitempty" toml:"addresses"`
	DisablePrivateDns bool     `json:"disable_private_dns"`
}
type FrontendAddress struct {
	CIDR string `json:"cidr" toml:"cidr"`
	Port string `json:"port" toml:"port"`
}

type CertSettings struct {
	DNSNames      []string `json:"dns_names" toml:"dns_names"`
	CustomTLSCert `json:"custom_tls_cert" toml:"custom_tls_cert"`
	Letsencrypt   bool `json:"letsencrypt" toml:"letsencrypt"`
}

type HTTPSettings struct {
	Enabled         bool `json:"enabled" toml:"enabled"`
	OIDCSettings    `json:"oidc_settings" toml:"oidc_settings"`
	HTTPHealthCheck `json:"http_health_check" toml:"http_health_check"`
	HTTPRedirect    `json:"http_redirect" toml:"http_redirect"`
	ExemptedPaths   `json:"exempted_paths" toml:"exempted_paths"`

	*CustomTrustCookie `json:"custom_trust_cookie,omitempty" toml:"custom_trust_cookie"`

	// Headers is a list of HTTP headers to add to every request sent to the Backend;
	// the key of the map is the header name, and the value is the header value you want.
	// The header value may be constructed using Go template syntax, such as {{.Email}}
	// referencing values in Banyan's JWT TrustToken.
	Headers  map[string]string `json:"headers" toml:"headers"`
	TokenLoc *TokenLocation    `json:"token_loc,omitempty" toml:"token_loc"`
}

type CustomTrustCookie struct {
	// SameSite: "", "default", "lax", "none", "strict"
	SameSite string `json:"same_site,omitempty"`
	// Path: override the default path of "/"
	Path string `json:"path,omitempty"`
}
type TokenLocation struct {
	QueryParam          string `json:"query_param,omitempty"`
	AuthorizationHeader bool   `json:"authorization_header,omitempty"`
	CustomHeader        string `json:"custom_header,omitempty"`
}

type ClientCIDRs struct {
	Addresses       []CIDRAddress       `json:"addresses" toml:"addresses"`
	HostTagSelector []map[string]string `json:"host_tag_selector" toml:"host_tag_selector"`
	Clusters        []string            `json:"clusters" toml:"clusters"`
}

type CIDRAddress struct {
	CIDR  string `json:"cidr" toml:"cidr"`
	Ports string `json:"ports" toml:"ports"`
}

type OIDCSettings struct {
	Enabled                         bool              `json:"enabled" toml:"enabled"`
	ServiceDomainName               string            `json:"service_domain_name" toml:"service_domain_name"`
	PostAuthRedirectPath            string            `json:"post_auth_redirect_path" toml:"post_auth_redirect_path"` // has default value "/"
	APIPath                         string            `json:"api_path" toml:"api_path"`                               // has default value "/api"
	TrustCallBacks                  map[string]string `json:"trust_callbacks" toml:"trust_callbacks"`                 //For multiple redirect URLs
	SuppressDeviceTrustVerification bool              `json:"suppress_device_trust_verification" toml:"suppress_device_trust_verification"`
}

type HTTPRedirect struct {
	Enabled     bool     `json:"enabled" toml:"enabled"`
	Addresses   []string `json:"addresses" toml:"addresses"`
	FromAddress []string `json:"from_address" toml:"from_address"`
	URL         string   `json:"url" toml:"url"`
	StatusCode  int      `json:"status_code" toml:"status_code"`
}

type HTTPHealthCheck struct {
	Enabled     bool     `json:"enabled" toml:"enabled"`
	Addresses   []string `json:"addresses" toml:"addresses"`
	Method      string   `json:"method" toml:"method"`
	Path        string   `json:"path" toml:"path"`
	UserAgent   string   `json:"user_agent" toml:"user_agent"`
	FromAddress []string `json:"from_address" toml:"from_address"`
	HTTPS       bool     `json:"https" toml:"https"`
}

// ExemptedPaths defines paths that are whitelisted/exempted from being checked by netagent/accesstier
type ExemptedPaths struct {
	Enabled  bool      `json:"enabled" toml:"enabled"`
	Paths    []string  `json:"paths,omitempty" toml:"paths"`
	Patterns []Pattern `json:"patterns,omitempty" toml:"patterns"`
}
type Pattern struct {
	Template         string   `json:"template,omitempty" toml:"template"`
	SourceCIDRs      []string `json:"source_cidrs,omitempty" toml:"source_cidrs"`
	Hosts            []Host   `json:"hosts" toml:"hosts"`
	Methods          []string `json:"methods" toml:"methods"`
	Paths            []string `json:"paths" toml:"paths"`
	MandatoryHeaders []string `json:"mandatory_headers" toml:"mandatory_headers"`
}

type Host struct {
	OriginHeader []string `json:"origin_header" toml:"origin_header"`
	Target       []string `json:"target" toml:"target"`
}

type CustomTLSCert struct {
	Enabled  bool   `json:"enabled" toml:"enabled"`
	CertFile string `json:"cert_file" toml:"cert_file"`
	KeyFile  string `json:"key_file" toml:"key_file"`
}

// OIDCClientInfo represents the Open ID Connect configuration of this service
// as an OIDC Relying on Party. Generated by restapi and recorded as a JSON string in
// mysqllib and common.RegisteredServiceInfo.OIDCClientSpec.
type OIDCClientInfo struct {
	// TrustAuth is the URL that netagent redirects the browser to when bnn_trust cookie is
	// missing.  https://<orgname>.trust.banyanops.com:8443/auth
	TrustAuth string `json:"trust_auth"`

	// TrustCB is the callback location issued by trustprovider to redirect back to the app.
	// Ex: https://app.myorg.com:443/bnn_trust_cb
	// (note the port number, which could be non-standard --
	// TODO: consider adding a field to OIDCSettings
	// specify the initial part, e.g., "https://app.myorg.com:443,
	// and have TrustCB only specify the path, e.g., "/bnn_trust_cb".
	// Alternatively, infer the domain name from Info.CertSettings.DNSNames
	// and the port number from Info.Attributes.Addresses?
	TrustCB                   string            `json:"trust_cb"`
	ClientID                  string            `json:"client_id"`                    // ClientID for Dex config
	ClientSecret              string            `json:"client_secret"`                // ClientSecret for Dex config
	TrustCallBacks            map[string]string `json:"trust_callbacks"`              // Stores multiple callback urls
	DisallowAsyncAuthRedirect bool              `json:"disallow_async_auth_redirect"` // (Dis)Allow async (native/sandbox app) auth
}

// ExpandedServiceInfo is unmarshaled element from services.json
type ExpandedServiceInfo struct {
	SvcInfo    *Info           `json:"service,omitempty"`
	OIDCClient *OIDCClientInfo `json:"oidc_client,omitempty"`
}

// TagSlice to hold all the Tags for Registered Service
type TagSlice []ResourceTag

// ResourceTag structure
type ResourceTag struct {
	ID        string `json:"id" toml:"id"`
	OrgID     string `json:"-" toml:"-"`
	ServiceID string `json:"-" toml:"-"`
	Name      string `json:"name" toml:"name"`
	Value     string `json:"value" toml:"value"`
}

type HostTag struct {
	ComBanyanopsHosttagSiteName string `json:"com.banyanops.hosttag.site_name"`
}

type Backend struct {
	// BackendTarget specifies the backend workload instance's address or name, ports, and TLS properties.
	BackendTarget `json:"target"`
	// BackendDNSOverrides is an optional section that specifies name-to-address or name-to-name mappings.
	// Name-to-address mapping could be used instead of DNS lookup. Format is "FQDN: ip_address".
	// Name-to-name mapping could be used to override one FQDN with the other. Format is "FQDN1: FQDN2"
	// Example: name-to-address -> "internal.myservice.com" : "10.23.0.1"
	//          name-to-name    ->    "exposed.service.com" : "internal.myservice.com"
	BackendDNSOverrides map[string]string `json:"dns_overrides"`
	// BackendWhitelist is an optional section that indicates the whitelisted/allowed names for
	// the backend workload instance. If this field is populated, then the backend name must
	// match at least one entry in this field list to establish connection with the backend service.
	// The names in this list are allowed to start with the wildcard character "*" to match more
	// than one backend name. This field is used for non-http-connect cases with backend names/FQDNs.
	// For httpConnect usecases where more advanced backend defining patterns are required,
	// plz use BackendAllowPatterns.
	BackendWhitelist []string `json:"whitelist"`
	// BackendAllowPatterns is an optional section defines the patterns for the backend workload
	// instance. If BackendWhitelist/BackendAllowPatterns are both not populated, then all backend
	// address/name/port are allowed. This field is effective only when BackendWhitelist is not populated.
	// If the BackendAllowPatterns is not populated, then the backend must match at least one entry
	// in this list to establish connection with the backend service.  This could be used
	// for both httpConnect and non-httpConnect cases.  In non-httpConnect cases only backend
	// hostnames are effective and other fields are ignored.
	BackendAllowPatterns []BackendAllowPattern `json:"allow_patterns,omitempty"`
	// HttpConnect is an optional setting that indicates to use HTTP Connect request to derive
	// the backend target address.
	HttpConnect bool `json:"http_connect,omitempty"`
	// ConnectorName indicates that the backend target is in the given connector's private network.
	ConnectorName string `json:"connector_name"`
}

type BackendTarget struct {
	// NameDelimiter is an optional string used to separate the initial component of
	// the frontend domain name into multiple parts, e.g., if name delimiter is "--" and
	// the frontend domain name is "abc--def.example.com", then the resulting parts are
	// "abc", "def", "example", and "com". These parts can be used in the backend target
	// name, e.g., "{{index .Parts 0}}.{{index .Parts 1}}.ec2.internal" (which would
	// get instantiated as "abc.def.ec2.internal").
	NameDelimiter string `json:"name_delimiter,omitempty" toml:"name_delimiter,omitempty"`
	// Name specifies the name of the backend workload instance.
	// If it is the empty string, then netagent will use the destination
	// IP address of the incoming frontend connection as the workload
	// instance's address.
	// If non-empty, Name can be a plain string, or a Go template string containing
	// "{{ .Name }}" and/or "{{ .Domain }}" for extracting portions
	// of the client SNI. For example, if SNI is "www.example.com",
	// the "{{ .Name }}" corresponds to "www" and the "{{ .Domain }}"
	// corresponds to "example.com".
	// As a concrete example, "{{ .Name }}-internal.{{ .Domain }}"
	// maps to "www-internal.example.com" for client SNI "www.example.com".
	Name string `json:"name"`
	// Port specifies the backend server's TCP port number.
	Port string `json:"port"`
	// TLS indicates whether the connection to the backend server uses TLS.
	TLS bool `json:"tls"`
	// TLSInsecure indicates whether the backend TLS connection does not validate the server's TLS certificate
	TLSInsecure bool `json:"tls_insecure"`
	// ClientCertificate indicates whether to provide netagent's client TLS certificate to the server if
	// the server asks for it in the TLS handshake.
	ClientCertificate bool `json:"client_certificate"`
}
type BackendAllowPattern struct {
	// Allowed hostnames my include a leading and/or trailing wildcard character "*"
	// to match multiple hostnames
	Hostnames []string `json:"hostnames,omitempty"`
	// Host may be a CIDR such as 10.1.1.0/24
	CIDRs []string `json:"cidrs,omitempty"`
	// List of allowed ports and port ranges
	Ports BackendAllowPorts `json:"ports,omitempty"`
}

type BackendAllowPorts struct {
	// List of allowed ports
	PortList []int `json:"port_list,omitempty"`
	// List of allowed port ranges
	PortRanges []PortRange `json:"port_ranges,omitempty"`
}

type PortRange struct {
	// Min and Max values of the port range
	Min int `json:"min"`
	Max int `json:"max"`
}
type CreateService struct {
	Kind       string   `json:"kind"`
	APIVersion string   `json:"apiVersion"`
	Type       string   `json:"type"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

type RegisteredServiceInfo struct {
	ServiceID        string // FullyQualified Service Name
	ServiceName      string
	FriendlyName     string
	ClusterName      string
	ServiceType      string
	ServiceDiscovery string
	ServiceVersion   int // monotonically incrementing on every update
	Description      string
	CreatedBy        string
	CreatedAt        int64
	LastUpdatedBy    string
	LastUpdatedAt    int64
	DeletedBy        string
	DeletedAt        int64
	External         string
	OIDCEnabled      string
	OIDCClientSpec   string // jsonified version of OIDCClientSpec
	ServiceSpec      string
	UserFacing       string
	Protocol         string
	Domain           string
	Port             uint
	Enabled          string
	IsDefault        bool
	OrgID            string
}

type GetServicesJson struct {
	ServiceID         string `json:"ServiceID"`
	ServiceName       string `json:"ServiceName"`
	ClusterName       string `json:"ClusterName"`
	ServiceType       string `json:"ServiceType"`
	ServiceDiscovery  string `json:"ServiceDiscovery"`
	ServiceVersion    int    `json:"ServiceVersion"`
	Description       string `json:"Description"`
	CreatedBy         string `json:"CreatedBy"`
	CreatedAt         int64  `json:"CreatedAt"`
	LastUpdatedBy     string `json:"LastUpdatedBy"`
	LastUpdatedAt     int64  `json:"LastUpdatedAt"`
	DeletedBy         string `json:"DeletedBy"`
	DeletedAt         int    `json:"DeletedAt"`
	External          string `json:"External"`
	OIDCEnabled       string `json:"OIDCEnabled"`
	OIDCClientSpec    string `json:"OIDCClientSpec"`
	UserFacing        string `json:"UserFacing"`
	Protocol          string `json:"Protocol"`
	Domain            string `json:"Domain"`
	Port              int    `json:"Port"`
	Enabled           string `json:"Enabled"`
	IsDefault         bool   `json:"IsDefault"`
	ServiceSpec       string `json:"ServiceSpec"`
	Spec              Spec
	CreateServiceSpec CreateService
}

type GetServiceSpec struct {
	ServiceID         string `json:"ServiceID"`
	ServiceName       string `json:"ServiceName"`
	ClusterName       string `json:"ClusterName"`
	ServiceType       string `json:"ServiceType"`
	ServiceDiscovery  string `json:"ServiceDiscovery"`
	ServiceVersion    int    `json:"ServiceVersion"`
	Description       string `json:"Description"`
	CreatedBy         string `json:"CreatedBy"`
	CreatedAt         int64  `json:"CreatedAt"`
	LastUpdatedBy     string `json:"LastUpdatedBy"`
	LastUpdatedAt     int64  `json:"LastUpdatedAt"`
	DeletedBy         string `json:"DeletedBy"`
	DeletedAt         int    `json:"DeletedAt"`
	External          string `json:"External"`
	OIDCEnabled       string `json:"OIDCEnabled"`
	OIDCClientSpec    string `json:"OIDCClientSpec"`
	UserFacing        string `json:"UserFacing"`
	Protocol          string `json:"Protocol"`
	Domain            string `json:"Domain"`
	Port              int    `json:"Port"`
	Enabled           string `json:"Enabled"`
	IsDefault         bool   `json:"IsDefault"`
	Spec              Spec
	CreateServiceSpec CreateService
}

type SecurityPoliciesResponse struct {
	PolicyID    string `json:"PolicyID"`
	PolicyName  string `json:"PolicyName"`
	PolicySpec  string `json:"PolicySpec"`
	Description string `json:"Description"`
}
