package accesstier

import (
	"errors"

	"github.com/jinzhu/copier"
)

const (
	SpecDefaultAccessTierLocalConfigKind = "BanyanAccessTierLocalConfig"
	SpecDefaultAPIVersion                = "rbac.banyanops.com/v1"
	SpecDefaultType                      = "attribute-based"
)

var (
	ErrSpecInvalidKind       = errors.New("spec contains invalid kind")
	ErrSpecInvalidAPIVersion = errors.New("spec contains invalid api version")
	ErrSpecInvalidType       = errors.New("spec contains invalid type")
)

type ATLcResponse struct {
	RequestId        string                `json:"request_id"`
	ErrorCode        int                   `json:"error_code"`
	ErrorDescription string                `json:"error_description"`
	Data             AccessTierLocalConfig `json:"data"`
}

type AccessTierLocalConfigSpec struct {
	Kind       string                        `json:"kind"`
	APIVersion string                        `json:"api_version"`
	Type       string                        `json:"type"`
	Metadata   AccessTierLocalConfigMetadata `json:"metadata"`
	Spec       AccessTierLocalConfig         `json:"spec"`
}

// Placeholder
type AccessTierLocalConfigMetadata struct{}

func (s AccessTierLocalConfigSpec) ValidateSpec() error {
	if s.Kind != SpecDefaultAccessTierLocalConfigKind {
		return ErrSpecInvalidKind
	}

	if s.APIVersion != SpecDefaultAPIVersion {
		return ErrSpecInvalidAPIVersion
	}

	if s.Type != SpecDefaultType {
		return ErrSpecInvalidType
	}

	return nil
}

// AccessTierLocalConfig is the configuration for an access tier. This used to
// be stored on the Netagent host within a YAML file, now it is distributed to
// Netagents when they initially start and contact their resident CC API URL.
type AccessTierLocalConfig struct {
	// Unused by client
	*BaseParameters `json:"base,omitempty"`

	// Parameters related to Netagent logging
	*LoggingParameters `json:"logging,omitempty"`

	// Parameters related to event rate limiting
	*EventParameters `json:"events,omitempty"`

	// Parameters related to hosted web service handling
	*HostedWebServiceParameters `json:"hosted_web_services,omitempty"`

	// Parameters related to infrastructure service handling
	*InfrastructureServiceParameters `json:"infrastructure_services,omitempty"`

	// Parameters related to denial-of-service protection
	*DoSProtectionParameters `json:"dos_protection,omitempty"`

	// Parameters related to debugging and serviceability
	*DebuggingParameters `json:"debugging,omitempty"`

	// ... everything else
	*MiscellaneousParameters `json:"miscellaneous,omitempty"`

	// Parameters related to service discovery
	*ServiceDiscoveryParameters `json:"service_discovery,omitempty"`

	// Unused by client
	// Initial spec for local config is saved
	Spec *string `json:"spec,omitempty"`
}

// NewAccessTierLocalConfigWithBase creates a new local config with base parameters filled
// This helper fills out defaults for other components of the local config
func NewAccessTierLocalConfigWithBase(shieldAddress, siteAddress string) *AccessTierLocalConfig {
	localConfig := NewDefaultAccessLocalConfig()
	localConfig.BaseParameters = &BaseParameters{
		ShieldAddress: &shieldAddress,
		SiteAddress:   &siteAddress,
	}
	return localConfig
}

// NewAccessTierLocalConfigWithoutBase creates a new local config with no base parameters filled
// This helper fills out defaults for other components of the local config
func NewAccessTierLocalConfigWithoutBase() *AccessTierLocalConfig {
	return NewDefaultAccessLocalConfig()
}

// NewDefaultAccessLocalConfig creates a local config with defaults filled out
// This does a deep copy so that separate local configs don't point to the same memory
// NOTE: If more sub-structs are added to AccessTierLocalConfig, an explicit copy should be added here
func NewDefaultAccessLocalConfig() *AccessTierLocalConfig {
	var (
		loggingParameters               = LoggingParameters{}
		eventParameters                 = EventParameters{}
		hostedWebServiceParameters      = HostedWebServiceParameters{}
		infrastructureServiceParameters = InfrastructureServiceParameters{}
		dosProtectionParameters         = DoSProtectionParameters{}
		debuggingParameters             = DebuggingParameters{}
		miscellaneousParameters         = MiscellaneousParameters{}
		serviceDiscoveryParameters      = ServiceDiscoveryParameters{}
	)
	copier.Copy(&loggingParameters, DefaultLoggingParameters)
	copier.Copy(&eventParameters, DefaultEventParameters)
	copier.Copy(&hostedWebServiceParameters, DefaultHostedWebServiceParameters)
	copier.Copy(&infrastructureServiceParameters, DefaultInfrastructureServiceParameters)
	copier.Copy(&dosProtectionParameters, DefaultDoSProtectionParameters)
	copier.Copy(&debuggingParameters, DefaultDebuggingParameters)
	copier.Copy(&miscellaneousParameters, DefaultMiscellaneousParameters)
	copier.Copy(&serviceDiscoveryParameters, DefaultServiceDiscoveryParameters)
	localConfig := AccessTierLocalConfig{
		LoggingParameters:               &loggingParameters,
		EventParameters:                 &eventParameters,
		HostedWebServiceParameters:      &hostedWebServiceParameters,
		InfrastructureServiceParameters: &infrastructureServiceParameters,
		DoSProtectionParameters:         &dosProtectionParameters,
		DebuggingParameters:             &debuggingParameters,
		MiscellaneousParameters:         &miscellaneousParameters,
		ServiceDiscoveryParameters:      &serviceDiscoveryParameters,
	}
	return &localConfig
}

func (atlc *AccessTierLocalConfig) AddHostTag(k, v string) {
	if atlc.HostTags == nil {
		atlc.HostTags = make(map[string]string)
	}
	atlc.HostTags[k] = v
}

// BaseParameters are filled in when we request a local config.
type BaseParameters struct {
	// Current access tier's associated shield address
	ShieldAddress *string `json:"shield_address,omitempty"`

	// Current access tier's site address
	SiteAddress *string `json:"site_address,omitempty"`
}

// LoggingParameters are parameters related to Netagent logging and
// metrics gathering.
type LoggingParameters struct {
	// Controls verbosity of logs to console
	ConsoleLogLevel *string `json:"console_log_level,omitempty" valid:"in(ERR|WARN|INFO|DEBUG)"`

	// Controls verbosity of logs to file
	FileLogLevel *string `json:"file_log_level,omitempty" valid:"in(ERR|WARN|INFO|DEBUG)"`

	// Whether to log to file or not
	FileLog *bool `json:"file_log,omitempty"`

	// For file logs: Number of files to use for log rotation
	LogNum *int `json:"log_num,omitempty"`

	// For file logs: Size of each file for log rotation
	LogSize *int `json:"log_size,omitempty"`

	// Enable or disable StatsD
	StatsD *bool `json:"statsd,omitempty"`

	// StatsD endpoint for use if StatsD is enabled
	StatsDAddress *string `json:"statsd_address,omitempty"`
}

// EventParameters are parameters related to Netagent rate limiting.
type EventParameters struct {
	// Enable or disable Netagent access event rate limiting
	CreditsLimiting *bool `json:"access_event_credits_limiting,omitempty"`

	// Number of credits to assign after an interval
	CreditsPerInterval *int `json:"access_event_credits_per_interval,omitempty"`

	// After this interval, assign number of credits per the above
	CreditsInterval *int `json:"access_event_credits_interval,omitempty"`

	// Maximum number of credits to assign a Netagent
	// One event consumes one credit
	CreditsMax *int `json:"access_event_credits_max,omitempty"`

	// Enable or disable Netagent access key event rate limiting
	KeyLimiting *bool `json:"access_event_key_limiting,omitempty"`

	// After this interval, another access key event may be generated
	KeyExpiration *int `json:"access_event_key_expiration,omitempty"`
}

// HostedWebServiceParameters are parameters related to this
// Netagent's handling of backend hosted web services.
type HostedWebServiceParameters struct {
	// Forward Banyan trust cookie to upstream servers
	ForwardTrustCookie *bool `json:"forward_trust_cookie,omitempty"`

	// Disable HTTP Strict Transport Security
	DisableHSTS *bool `json:"disable_hsts,omitempty"`
}

// InfrastructureServiceParameters are parameters related to this
// Netagent's handling of backend infrastructure services.
type InfrastructureServiceParameters struct {
	// Maximum lifetime for TCP sockets handled by Netagent
	MaximumSessionTimeout *int `json:"maximum_session_timeout,omitempty"`
}

// DoSProtectionParameters are parameters related to denial of
// service protection.
type DoSProtectionParameters struct {
	// Enable or disable DoS protection
	BadActor *bool `json:"bad_actor,omitempty"`

	// Number of unauthorized requests before an offending IP address is jailed
	InfractionCount *int `json:"infraction_count,omitempty"`

	// Jail interval after which bad actor is freed
	SentenceTime *int `json:"sentence_time,omitempty"`
}

// DebuggingParameters are parameters related to debugging
// Netagents. These may affect performance and throughput so should be used
// with caution outside of default values.
type DebuggingParameters struct {
	// Verbose logging for HTTP backend traffic
	HTTPBackendLog *bool `json:"http_backend_log,omitempty"`

	// Enable or disable visibility mode
	// If on, Netagent will not do policy enforcement on inbound traffic
	VisibilityOnly *bool `json:"visibility_only,omitempty"`

	// If Shield is not available, policies will be treated as if they are permissive
	// Zero means this is disabled
	ShieldTimeout *int `json:"shield_timeout,omitempty"`

	// Enable TCP keepalive messages for TCP sockets handled by Netagent
	KeepAlive *bool `json:"keep_alive,omitempty"`

	// Idle time before sending a TCP keepalive
	KeepIdle *int `json:"keep_idle,omitempty"`

	// Time between consecutive TCP keepalive messages
	KeepInterval *int `json:"keep_interval,omitempty"`

	// Number of missing TCP keepalive acknowledgements before closing connection
	KeepCount *int `json:"keep_count,omitempty"`

	// Output file for CPU profiling; may impact performance
	// If empty, this is disabled
	CPUProfile *string `json:"cpu_profile,omitempty"`

	// Output file for memory profiling; may impact performance
	// If empty, this is disabled
	MemProfile *bool `json:"mem_profile,omitempty"`

	// Host only mode
	HostOnly *bool `json:"host_only,omitempty"`

	// Disable Docker monitoring
	DisableDocker *bool `json:"disable_docker,omitempty"`

	// Send all-zero data points to Shield
	SendZeros *bool `json:"send_zeros,omitempty"`

	// Interval for reporting statistics
	Period *int `json:"period,omitempty"`

	// Generate access events at the request level
	RequestLevelEvents *bool `json:"request_level_events,omitempty"`

	// Provide client address transparency
	AddressTransparency *bool `json:"address_transparency,omitempty"`

	// Netagent will generate RSA instead of ECDSA keys
	UseRSA *bool `json:"use_rsa,omitempty"`

	// Include non-root (intermediate) CA certs during TLS handshakes
	FullServerCertChain *bool `json:"full_server_cert_chain,omitempty"`

	// Enable or disable OpenID Connect
	CodeFlow *bool `json:"code_flow,omitempty"`

	// HTTP inactivity timeout
	InactivityTimeout *int `json:"inactivity_timeout,omitempty"`

	// Client identification timeout
	ClientTimeout *int `json:"client_timeout,omitempty"`
}

// MiscellaneousParameters are general parameters that don't fit in
// a specific category.
type MiscellaneousParameters struct {
	// Enable or disable access tier mode
	// If disabled, then uses host agent mode
	AccessTier *bool `json:"access_tier,omitempty"`

	// Arbitrary key-value pairs used for attribute matching on Netagent
	HostTags map[string]string `json:"host_tags,omitempty"`

	// TCP listen port on Netagent host for proxying incoming connections
	ListenPort *int `json:"listen_port,omitempty" valid:"range(1024|65535)"`

	// TCP listen port on Netagent host for health checks
	ListenPortHealth *int `json:"listen_port_health,omitempty" valid:"range(1024|65535)"`

	// Establish control connection to Shield using HTTP CONNECT proxy
	// Overrides HTTPS_PROXY environment variable
	HTTPSProxy *string `json:"https_proxy,omitempty"`

	// Configures how Netagent will determine its public IP
	PublicIPSource *string `json:"public_ip_source,omitempty" valid:"in(AWS|GCE|default|none)"`

	// Max percentage of CPU core usage
	CPULimit *int `json:"cpu_limit,omitempty" valid:"range(1|100)"`

	// Whether WireGuard should use a userspace or kernel space module
	UserModeTunnel *bool `json:"user_mode_tunnel,omitempty"`

	// Source NAT support
	EnduserTunnelCIDR *string `json:"enduser_tunnel_cidr,omitempty"`
}

type ServiceDiscoveryParameters struct {
	// Enable or disable DNS and conntrack logging
	ServiceDiscoveryEnable *bool `json:"service_discovery_enable,omitempty"`

	// Message threshold for batch processing
	ServiceDiscoveryMsgLimit *int `json:"service_discovery_msg_limit,omitempty" valid:"in(100|1000|5000)"`

	// Timeout value for batch prod3wwint
	ServiceDiscoveryMsgTimeout *int `json:"service_discovery_msg_timeout,omitempty"`
}

// Always filled in when local config is retrieved via API call
var DefaultBaseParameters = &BaseParameters{
	ShieldAddress: nil,
	SiteAddress:   nil,
}

var DefaultLoggingParameters = LoggingParameters{
	ConsoleLogLevel: StringPtr("ERR"),
	FileLogLevel:    StringPtr("INFO"),
	FileLog:         BoolPtr(true),
	LogNum:          IntPtr(10),
	LogSize:         IntPtr(50),
	StatsD:          BoolPtr(false),
	StatsDAddress:   StringPtr("127.0.0.1:8125"),
}

var DefaultEventParameters = EventParameters{
	CreditsLimiting:    BoolPtr(true),
	CreditsPerInterval: IntPtr(5),
	CreditsInterval:    IntPtr(60),
	CreditsMax:         IntPtr(5000), // Docs incorrect: 1k -> 5k
	KeyLimiting:        BoolPtr(true),
	KeyExpiration:      IntPtr(540),
}

var DefaultHostedWebServiceParameters = HostedWebServiceParameters{
	ForwardTrustCookie: BoolPtr(false),
	DisableHSTS:        BoolPtr(false),
}

var DefaultInfrastructureServiceParameters = InfrastructureServiceParameters{
	MaximumSessionTimeout: IntPtr(43200),
}

var DefaultDoSProtectionParameters = DoSProtectionParameters{
	BadActor:        BoolPtr(false),
	InfractionCount: IntPtr(10),
	SentenceTime:    IntPtr(600),
}

var DefaultDebuggingParameters = DebuggingParameters{
	HTTPBackendLog:      BoolPtr(false),
	VisibilityOnly:      BoolPtr(false),
	ShieldTimeout:       IntPtr(0),
	KeepAlive:           BoolPtr(true),
	KeepIdle:            IntPtr(59),
	KeepInterval:        IntPtr(59),
	KeepCount:           IntPtr(3),
	CPUProfile:          StringPtr(""),
	MemProfile:          BoolPtr(false),
	HostOnly:            BoolPtr(true),
	DisableDocker:       BoolPtr(false),
	SendZeros:           BoolPtr(false),
	Period:              IntPtr(20),
	RequestLevelEvents:  BoolPtr(true),
	AddressTransparency: BoolPtr(true),
	UseRSA:              BoolPtr(false),
	FullServerCertChain: BoolPtr(true),
	CodeFlow:            BoolPtr(false),
	InactivityTimeout:   IntPtr(3600),
	ClientTimeout:       IntPtr(20),
}

var DefaultMiscellaneousParameters = MiscellaneousParameters{
	AccessTier:        BoolPtr(true),
	HostTags:          nil,
	ListenPort:        IntPtr(9999),
	ListenPortHealth:  IntPtr(9998),
	HTTPSProxy:        StringPtr(""),
	PublicIPSource:    StringPtr("default"),
	CPULimit:          IntPtr(100),
	UserModeTunnel:    BoolPtr(false),
	EnduserTunnelCIDR: StringPtr("100.64.0.0/11"),
}

var DefaultServiceDiscoveryParameters = ServiceDiscoveryParameters{
	ServiceDiscoveryEnable:     BoolPtr(false),
	ServiceDiscoveryMsgLimit:   IntPtr(100),
	ServiceDiscoveryMsgTimeout: DurationPtr(10),
}

// StringPtr creates a pointer from incoming string
// Avoids the need to create local variables for literals
func StringPtr(s string) *string {
	return &s
}

// IntPtr creates a pointer from an incoming int
func IntPtr(i int) *int {
	return &i
}

// BoolPtr creates a pointer from an incoming bool
func BoolPtr(b bool) *bool {
	return &b
}

// DurationPtr creates a pointer from an incoming int
func DurationPtr(t int) *int {
	return &t
}
