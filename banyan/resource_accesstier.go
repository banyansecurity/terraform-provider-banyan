package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/pkg/errors"
	"log"
	"reflect"
)

func resourceAccessTier() *schema.Resource {
	return &schema.Resource{
		Description:   "",
		CreateContext: resourceAccessTierCreate,
		ReadContext:   resourceAccessTierRead,
		UpdateContext: resourceAccessTierUpdate,
		DeleteContext: resourceAccessTierDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the access tier",
				ForceNew:    true,
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the access tier in Banyan",
				ForceNew:    true,
			},
			"cluster": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "",
				ForceNew:    true,
			},
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Public address of the access tier",
			},
			"disable_snat": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disable Source Network Address Translation (SNAT)",
			},
			"src_nat_cidr_range": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"api_key_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "",
			},
			"tunnel_connector_port": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "UDP for for connectors to this access tier to utilize",
				ValidateFunc: validatePort(),
			},
			"tunnel_enduser_dns_search_domains": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "",
			},
			"tunnel_enduser_port": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "UDP for for end users to this access tier to utilize",
				ValidateFunc: validatePort(),
			},
			"tunnel_enduser_dns_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "",
				Default:     false,
			},
			"tunnel_enduser_cidrs": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"console_log_level": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Controls verbosity of logs to console",
				ValidateFunc: validation.StringInSlice([]string{"ERR", "WARN", "INFO", "DEBUG"}, false),
			},
			"file_log_level": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Controls verbosity of logs to file",
				ValidateFunc: validation.StringInSlice([]string{"ERR", "WARN", "INFO", "DEBUG"}, false),
			},
			"file_log": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether to log to file or not",
			},
			"log_num": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "For file logs: Number of files to use for log rotation",
			},
			"log_size": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "For file logs: Size of each file for log rotation",
			},
			"statsd": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable or disable StatsD",
			},
			"statsd_address": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "StatsD endpoint for use if StatsD is enabled",
				ValidateFunc: validation.IsIPv4Address,
			},
			"access_event_credits_limiting": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable or disable Netagent access event rate limiting",
			},
			"access_event_key_limiting": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable or disable Netagent access key event rate limiting",
			},
			"forward_trust_cookie": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Forward Banyan trust cookie to upstream servers",
			},
			"disable_hsts": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disable HTTP Strict Transport Security",
			},
			"infra_maximum_session_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "",
			},
			"debug_http_backend_log": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Verbose logging for HTTP backend traffic",
			},
			"debug_visibility_only": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable or disable visibility mode. If on, Netagent will not do policy enforcement on inbound traffic",
			},
			"debug_shield_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "If Shield is not available, policies will be treated as if they are permissive. Zero means this is disabled.",
			},
			"debug_keep_alive": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable TCP keepalive messages for TCP sockets handled by Netagent",
			},
			"debug_keep_idle": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Idle time before sending a TCP keepalive",
			},
			"debug_keep_interval": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Time between consecutive TCP keepalive messages",
			},
			"debug_keep_count": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of missing TCP keepalive acknowledgements before closing connection",
			},
			"debug_cpu_profile": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Output file for CPU profiling; may impact performance. If empty, this is disabled",
			},
			"debug_mem_profile": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Output file for memory profiling; may impact performance. If empty, this is disabled",
			},
			"debug_host_only": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Host only mode",
			},
			"debug_disable_docker": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Disable Docker monitoring",
			},
			"debug_send_zeros": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Send all-zero data points to Shield",
			},
			"debug_period": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Interval for reporting statistics",
			},
			"debug_request_level_events": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Generate access events at the request level",
			},
			"debug_address_transparency": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Provide client address transparency",
			},
			"debug_use_rsa": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Netagent will generate RSA instead of ECDSA keys",
			},
			"debug_full_server_cert_chain": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Include non-root (intermediate) CA certs during TLS handshakes",
			},
			"debug_code_flow": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable or disable OpenID Connect",
			},
			"debug_inactivity_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "HTTP inactivity timeout",
			},
			"debug_client_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Client identification timeout",
			},
			"debug_service_discovery_enable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable or disable DNS and conntrack logging",
			},
			"debug_service_discovery_msg_limit": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Message threshold for batch processing",
				ValidateFunc: validation.IntInSlice([]int{100, 1000, 5000}),
			},
			"debug_service_discovery_msg_timeout": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Timeout value for service discovery batch processing",
			},
		},
	}
}

func updateLocalConfig(d *schema.ResourceData, c *client.Holder, state accesstier.AccessTierInfo) (diagnostics diag.Diagnostics) {
	createdLocalConfig, err := c.AccessTier.GetLocalConfig(state.Name)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't retrieve local config for access tier"))
	}
	lc := accesstier.AccessTierLocalConfig{
		BaseParameters: &accesstier.BaseParameters{
			ShieldAddress: createdLocalConfig.ShieldAddress,
			SiteAddress:   createdLocalConfig.SiteAddress,
		},
		LoggingParameters:               expandLogging(d),
		EventParameters:                 expandEventParameters(d),
		HostedWebServiceParameters:      expandHostedWebServices(d),
		InfrastructureServiceParameters: expandInfrastructureService(d),
		DebuggingParameters:             expandDebugging(d),
	}
	_, err = c.AccessTier.UpdateLocalConfig(state.Name, lc)
	if err != nil {
		return diag.FromErr(errors.Errorf("failed to update local configuration for %s", state.Name))
	}
	return
}

func resourceAccessTierCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("creating access tier %s : %s", d.Get("name"), d.Id())
	c := m.(*client.Holder)
	post := atFromState(c, d)
	state, err := c.AccessTier.Create(*post)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new access tier"))
	}
	updateLocalConfig(d, c, state)
	log.Printf("created access tier %s : %s", state.Name, d.Id())
	diagnostics = resourceAccessTierRead(ctx, d, m)
	d.SetId(state.ID)
	return
}

func resourceAccessTierRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("reading access tier %t : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	at, err := client.AccessTier.Get(d.Id())
	if err != nil {
		return handleNotFoundError(d, fmt.Sprintf("access tier %q", d.Id()))
	}
	d.SetId(at.ID)
	cluster, err := client.Shield.GetAll()
	if err != nil {
		return diag.FromErr(err)
	}
	d.Set("cluster", cluster[0])
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("name", at.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("address", at.Address)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("disable_snat", at.DisableSnat)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("src_nat_cidr_range", at.SrcNATCIDRRange)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("api_key_id", at.APIKeyID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenTunnelConfigSatellite(d, &at)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenTunnelConfigEndUser(d, &at)
	if err != nil {
		return diag.FromErr(err)
	}

	// Now get the local config
	atLocalConfig, err := client.AccessTier.GetLocalConfig(at.Name)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't read access tier local config"))
	}
	err = flattenLoggingParameters(d, atLocalConfig)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenEventParameters(d, atLocalConfig)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenInfrastructureServiceParameters(d, atLocalConfig)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenDebuggingParameters(d, atLocalConfig)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("read access tier %s : %s", d.Get("name"), d.Id())
	return
}

func atFromState(c *client.Holder, d *schema.ResourceData) (accessTier *accesstier.AccessTierPost) {
	cluster, err := c.Shield.GetAll()
	if err != nil {
		return nil
	}
	at := accesstier.AccessTierPost{
		Name:            d.Get("name").(string),
		Address:         d.Get("address").(string),
		TunnelSatellite: expandTunnelConfigSatellite(d),
		TunnelEnduser:   expandTunnelConfigEndUser(d),
		ClusterName:     cluster[0],
		DisableSnat:     d.Get("disable_snat").(bool),
		SrcNATCIDRRange: d.Get("src_nat_cidr_range").(string),
		ApiKeyId:        d.Get("api_key_id").(string),
	}
	return &at
}

func resourceAccessTierUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("updating access tier %s : %s", d.Get("name"), d.Id())
	c := m.(*client.Holder)
	at := atFromState(c, d)
	state, err := c.AccessTier.Update(d.Id(), *at)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't update access tier"))
	}
	updateLocalConfig(d, c, state)
	log.Printf("updated access tier %s : %s", at.Name, d.Id())
	d.SetId(state.ID)
	return
}

func resourceAccessTierDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("deleting access tier %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	err := client.AccessTier.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Printf("deleted access tier %s : %s", d.Get("name"), d.Id())
	d.SetId("")
	return
}

func expandTunnelConfigSatellite(d *schema.ResourceData) (expanded *accesstier.AccessTierTunnelInfoPost) {
	e := accesstier.AccessTierTunnelInfoPost{
		UDPPortNumber: d.Get("tunnel_connector_port").(int),
	}
	if reflect.DeepEqual(e, accesstier.AccessTierTunnelInfoPost{}) {
		return nil
	}
	return &e
}

func expandTunnelConfigEndUser(d *schema.ResourceData) (expanded *accesstier.AccessTierTunnelInfoPost) {
	e := accesstier.AccessTierTunnelInfoPost{
		UDPPortNumber:    d.Get("tunnel_enduser_port").(int),
		DNSSearchDomains: d.Get("tunnel_enduser_dns_search_domains").(string),
		DNSEnabled:       d.Get("tunnel_enduser_dns_enabled").(bool),
		CIDRs:            convertSchemaSetToStringSlice(d.Get("tunnel_enduser_cidrs").(*schema.Set)),
	}
	if reflect.DeepEqual(e, accesstier.AccessTierTunnelInfoPost{}) {
		return nil
	}
	return &e
}

func expandLogging(d *schema.ResourceData) (expanded *accesstier.LoggingParameters) {
	ConsoleLogLevel := d.Get("console_log_level").(string)
	FileLogLevel := d.Get("file_log_level").(string)
	FileLog := d.Get("file_log").(bool)
	LogNum := d.Get("log_num").(int)
	LogSize := d.Get("log_size").(int)
	StatsD := d.Get("statsd").(bool)
	StatsDAddress := d.Get("statsd_address").(string)

	e := accesstier.LoggingParameters{
		ConsoleLogLevel: &ConsoleLogLevel,
		FileLogLevel:    &FileLogLevel,
		FileLog:         &FileLog,
		LogNum:          &LogNum,
		LogSize:         &LogSize,
		StatsD:          &StatsD,
		StatsDAddress:   &StatsDAddress,
	}
	return &e
}

func expandEventParameters(d *schema.ResourceData) (expanded *accesstier.EventParameters) {
	CreditsLimiting := d.Get("access_event_credits_limiting").(bool)
	KeyLimiting := d.Get("access_event_key_limiting").(bool)
	e := accesstier.EventParameters{
		CreditsLimiting: &CreditsLimiting,
		KeyLimiting:     &KeyLimiting,
	}
	return &e
}

func expandHostedWebServices(d *schema.ResourceData) (expanded *accesstier.HostedWebServiceParameters) {
	ForwardTrustCookie := d.Get("forward_trust_cookie").(bool)
	DisableHSTS := d.Get("disable_hsts").(bool)
	e := accesstier.HostedWebServiceParameters{
		ForwardTrustCookie: &ForwardTrustCookie,
		DisableHSTS:        &DisableHSTS,
	}
	return &e
}

func expandInfrastructureService(d *schema.ResourceData) (expanded *accesstier.InfrastructureServiceParameters) {
	MaximumSessionTimeout := d.Get("infra_maximum_session_timeout").(int)

	e := accesstier.InfrastructureServiceParameters{
		MaximumSessionTimeout: &MaximumSessionTimeout,
	}
	return &e
}

func expandDebugging(d *schema.ResourceData) (expanded *accesstier.DebuggingParameters) {
	HTTPBackendLog := d.Get("debug_http_backend_log").(bool)
	VisibilityOnly := d.Get("debug_visibility_only").(bool)
	ShieldTimeout := d.Get("debug_shield_timeout").(int)
	KeepAlive := d.Get("debug_keep_alive").(bool)
	KeepIdle := d.Get("debug_keep_idle").(int)
	KeepInterval := d.Get("debug_keep_interval").(int)
	KeepCount := d.Get("debug_keep_count").(int)
	CPUProfile := d.Get("debug_cpu_profile").(string)
	MemProfile := d.Get("debug_mem_profile").(bool)
	HostOnly := d.Get("debug_host_only").(bool)
	DisableDocker := d.Get("debug_disable_docker").(bool)
	SendZeros := d.Get("debug_send_zeros").(bool)
	Period := d.Get("debug_period").(int)
	RequestLevelEvents := d.Get("debug_request_level_events").(bool)
	AddressTransparency := d.Get("debug_address_transparency").(bool)
	UseRSA := d.Get("debug_use_rsa").(bool)
	FullServerCertChain := d.Get("debug_full_server_cert_chain").(bool)
	CodeFlow := d.Get("debug_code_flow").(bool)
	InactivityTimeout := d.Get("debug_inactivity_timeout").(int)
	ClientTimeout := d.Get("debug_client_timeout").(int)

	e := accesstier.DebuggingParameters{
		HTTPBackendLog:      &HTTPBackendLog,
		VisibilityOnly:      &VisibilityOnly,
		ShieldTimeout:       &ShieldTimeout,
		KeepAlive:           &KeepAlive,
		KeepIdle:            &KeepIdle,
		KeepInterval:        &KeepInterval,
		KeepCount:           &KeepCount,
		CPUProfile:          &CPUProfile,
		MemProfile:          &MemProfile,
		HostOnly:            &HostOnly,
		DisableDocker:       &DisableDocker,
		SendZeros:           &SendZeros,
		Period:              &Period,
		RequestLevelEvents:  &RequestLevelEvents,
		AddressTransparency: &AddressTransparency,
		UseRSA:              &UseRSA,
		FullServerCertChain: &FullServerCertChain,
		CodeFlow:            &CodeFlow,
		InactivityTimeout:   &InactivityTimeout,
		ClientTimeout:       &ClientTimeout,
	}
	return &e
}

func flattenDebuggingParameters(d *schema.ResourceData, atLocalConfig accesstier.AccessTierLocalConfig) (err error) {
	if isNil(atLocalConfig.LoggingParameters) {
		return
	}
	err = d.Set("debug_http_backend_log", atLocalConfig.DebuggingParameters.HTTPBackendLog)
	if err != nil {
		return
	}
	err = d.Set("debug_visibility_only", atLocalConfig.DebuggingParameters.VisibilityOnly)
	if err != nil {
		return
	}
	err = d.Set("debug_shield_timeout", atLocalConfig.DebuggingParameters.ShieldTimeout)
	if err != nil {
		return
	}
	err = d.Set("debug_keep_alive", atLocalConfig.DebuggingParameters.KeepAlive)
	if err != nil {
		return
	}
	err = d.Set("debug_keep_idle", atLocalConfig.DebuggingParameters.KeepIdle)
	if err != nil {
		return
	}
	err = d.Set("debug_keep_interval", atLocalConfig.DebuggingParameters.KeepInterval)
	if err != nil {
		return
	}
	err = d.Set("debug_keep_count", atLocalConfig.DebuggingParameters.KeepCount)
	if err != nil {
		return
	}
	err = d.Set("debug_cpu_profile", atLocalConfig.DebuggingParameters.CPUProfile)
	if err != nil {
		return
	}
	err = d.Set("debug_mem_profile", atLocalConfig.DebuggingParameters.MemProfile)
	if err != nil {
		return
	}
	err = d.Set("debug_host_only", atLocalConfig.DebuggingParameters.HostOnly)
	if err != nil {
		return
	}
	err = d.Set("debug_disable_docker", atLocalConfig.DebuggingParameters.DisableDocker)
	if err != nil {
		return
	}
	err = d.Set("debug_send_zeros", atLocalConfig.DebuggingParameters.SendZeros)
	if err != nil {
		return
	}
	err = d.Set("debug_period", atLocalConfig.DebuggingParameters.Period)
	if err != nil {
		return
	}
	err = d.Set("debug_request_level_events", atLocalConfig.DebuggingParameters.RequestLevelEvents)
	if err != nil {
		return
	}
	err = d.Set("debug_address_transparency", atLocalConfig.DebuggingParameters.AddressTransparency)
	if err != nil {
		return
	}
	err = d.Set("debug_use_rsa", atLocalConfig.DebuggingParameters.UseRSA)
	if err != nil {
		return
	}
	err = d.Set("debug_full_server_cert_chain", atLocalConfig.DebuggingParameters.FullServerCertChain)
	if err != nil {
		return
	}
	err = d.Set("debug_code_flow", atLocalConfig.DebuggingParameters.CodeFlow)
	if err != nil {
		return
	}
	err = d.Set("debug_inactivity_timeout", atLocalConfig.DebuggingParameters.InactivityTimeout)
	if err != nil {
		return
	}
	err = d.Set("debug_client_timeout", atLocalConfig.DebuggingParameters.ClientTimeout)
	if err != nil {
		return
	}
	return
}

func flattenInfrastructureServiceParameters(d *schema.ResourceData, atLocalConfig accesstier.AccessTierLocalConfig) (err error) {
	if isNil(atLocalConfig.InfrastructureServiceParameters) {
		return
	}
	err = d.Set("infra_maximum_session_timeout", atLocalConfig.InfrastructureServiceParameters.MaximumSessionTimeout)
	if err != nil {
		return
	}
	return
}

func flattenEventParameters(d *schema.ResourceData, atLocalConfig accesstier.AccessTierLocalConfig) (err error) {
	if isNil(atLocalConfig.EventParameters) {
		return
	}
	err = d.Set("access_event_credits_limiting", atLocalConfig.EventParameters.CreditsLimiting)
	if err != nil {
		return
	}
	err = d.Set("access_event_credits_per_interval", atLocalConfig.EventParameters.CreditsPerInterval)
	if err != nil {
		return
	}
	err = d.Set("access_event_credits_interval", atLocalConfig.EventParameters.CreditsInterval)
	if err != nil {
		return
	}
	err = d.Set("access_event_credits_max", atLocalConfig.EventParameters.CreditsMax)
	if err != nil {
		return
	}
	err = d.Set("access_event_key_limiting", atLocalConfig.EventParameters.KeyLimiting)
	if err != nil {
		return
	}
	err = d.Set("access_event_key_expiration", atLocalConfig.EventParameters.KeyExpiration)
	if err != nil {
		return
	}
	return
}

func flattenLoggingParameters(d *schema.ResourceData, atLocalConfig accesstier.AccessTierLocalConfig) (err error) {
	if isNil(atLocalConfig.LoggingParameters) {
		return
	}
	err = d.Set("console_log_level", atLocalConfig.LoggingParameters.ConsoleLogLevel)
	if err != nil {
		return
	}
	err = d.Set("file_log_level", atLocalConfig.LoggingParameters.FileLogLevel)
	if err != nil {
		return
	}
	err = d.Set("file_log", atLocalConfig.LoggingParameters.FileLog)
	if err != nil {
		return
	}
	err = d.Set("log_num", atLocalConfig.LoggingParameters.LogNum)
	if err != nil {
		return
	}
	err = d.Set("log_size", atLocalConfig.LoggingParameters.LogSize)
	if err != nil {
		return
	}
	err = d.Set("statsd", atLocalConfig.LoggingParameters.StatsD)
	if err != nil {
		return
	}
	err = d.Set("statsd_address", atLocalConfig.LoggingParameters.StatsDAddress)
	if err != nil {
		return
	}
	return
}

func flattenTunnelConfigSatellite(d *schema.ResourceData, at *accesstier.AccessTierInfo) (err error) {
	if isNil(at.TunnelSatellite) {
		return
	}
	err = d.Set("tunnel_connector_port", at.TunnelSatellite.UDPPortNumber)
	if err != nil {
		return
	}
	return
}

func flattenTunnelConfigEndUser(d *schema.ResourceData, at *accesstier.AccessTierInfo) (err error) {
	if isNil(at.TunnelEnduser) {
		return
	}
	err = d.Set("tunnel_enduser_port", at.TunnelEnduser.UDPPortNumber)
	if err != nil {
		return
	}
	err = d.Set("tunnel_enduser_dns_search_domains", at.TunnelEnduser.DNSSearchDomains)
	if err != nil {
		return
	}
	err = d.Set("tunnel_enduser_dns_enabled", at.TunnelEnduser.DNSEnabled)
	if err != nil {
		return
	}
	err = d.Set("tunnel_enduser_cidrs", at.TunnelEnduser.CIDRs)
	if err != nil {
		return
	}
	return
}
