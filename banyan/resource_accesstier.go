package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"reflect"
	"time"
)

func resourceAccessTier() *schema.Resource {
	return &schema.Resource{
		Description:   "The access tier resource allows for configuration of the access tier API object. We recommend utilizing the banyansecurity/banyan-accesstier2 terraform registry module specific to your cloud provider. For more information about the access tier see the [documentation](https://docs.banyansecurity.io/docs/banyan-components/accesstier/)",
		CreateContext: resourceAccessTierCreate,
		ReadContext:   resourceAccessTierRead,
		UpdateContext: resourceAccessTierUpdate,
		DeleteContext: resourceAccessTierDelete,
		Schema:        AccessTierSchema(),
	}
}

func AccessTierSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
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
			Optional:    true,
			Description: "Cluster / shield name in Banyan. If not provided then the cluster will be chosen automatically",
			ForceNew:    true,
			Default:     "",
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
			Description: "CIDR range which source Network Address Translation (SNAT) will be disabled for",
		},
		"api_key_id": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "ID of the API key which is scoped to access tier",
		},
		"tunnel_connector_port": {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "UDP port for connectors to associated with this access tier to utilize",
			ValidateFunc: validatePort(),
		},
		"tunnel_cidrs": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Backend CIDR Ranges that correspond to the IP addresses in your private network(s)",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"tunnel_private_domains": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Any internal domains that can only be resolved on your internal network’s private DNS",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"console_log_level": {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Controls verbosity of logs to console. Must be one of \"ERR\", \"WARN\", \"INFO\", \"DEBUG\"",
			ValidateFunc: validation.StringInSlice([]string{"ERR", "WARN", "INFO", "DEBUG"}, false),
		},
		"file_log_level": {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Controls verbosity of logs to file. Must be one of \"ERR\", \"WARN\", \"INFO\", \"DEBUG\"",
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
		"statsd_address": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Address to send statsd messages: “hostname:port” for UDP, “unix:///path/to/socket” for UDS",
		},
		"events_rate_limiting": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enable rate limiting of Access Event generation based on a credit-based rate control mechanism",
		},
		"event_key_rate_limiting": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enable rate limiting of Access Event generation based on a credit-based rate control mechanism",
		},
		"forward_trust_cookie": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Forward the Banyan trust cookie to upstream servers. This may be enabled if upstream servers wish to make use of information in the Banyan trust cookie.",
		},
		"enable_hsts": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "If enabled, Banyan will send the HTTP Strict-Transport-Security response header",
		},
		"infra_maximum_session_timeout": {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "Timeout in seconds infrastructure sessions connected via the access tier",
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
	}
	return s
}

func updateLocalConfig(d *schema.ResourceData, c *client.Holder, spec accesstier.AccessTierInfo) (diagnostics diag.Diagnostics) {
	currentLc, err := c.AccessTier.GetLocalConfig(spec.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	lc := accesstier.AccessTierLocalConfig{
		BaseParameters: &accesstier.BaseParameters{
			ShieldAddress: currentLc.ShieldAddress,
			SiteAddress:   currentLc.SiteAddress,
		},
		LoggingParameters:               expandLogging(d),
		EventParameters:                 expandEventParameters(d),
		HostedWebServiceParameters:      expandHostedWebServices(d),
		InfrastructureServiceParameters: expandInfrastructureService(d),
		DebuggingParameters:             expandDebugging(d),
	}
	// Combining local config with accesstier facing config
	_, err = c.AccessTier.UpdateLocalConfig(spec.ID, lc)
	if err != nil {
		return diag.Errorf("failed to update local configuration for %s", spec.Name)
	}
	return
}

func resourceAccessTierCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	clusterName, err := setAccessTierCluster(c, d)
	if err != nil {
		return diag.FromErr(err)
	}
	spec, err := c.AccessTier.Create(atFromState(d, clusterName))
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = updateLocalConfig(d, c, spec)
	d.SetId(spec.ID)
	return
}

// automatically set the cluster unless it is specified
func setAccessTierCluster(c *client.Holder, d *schema.ResourceData) (clusterName string, err error) {
	_, ok := d.GetOk("cluster")
	if !ok {
		clusterName, err = getFirstCluster(c)
		return
	}
	clusterName = d.Get("cluster").(string)
	clusters, err := c.Shield.GetAll()
	if err != nil {
		return
	}
	if !contains(clusters, clusterName) {
		err = fmt.Errorf("no cluster with name %s found. valid cluster names for org: %s", clusterName, clusters)
	}
	return
}

func resourceAccessTierRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	at, err := c.AccessTier.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	d.SetId(at.ID)
	// we do not read the cluster
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
	atLocalConfig, err := c.AccessTier.GetLocalConfig(at.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenLoggingParameters(d, atLocalConfig)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenEventParameters(d, atLocalConfig)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenWebServices(d, atLocalConfig)
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
	return
}

// creates an access tier from the terraform state
func atFromState(d *schema.ResourceData, clusterName string) (accessTier accesstier.AccessTierPost) {
	at := accesstier.AccessTierPost{
		Name:            d.Get("name").(string),
		Address:         d.Get("address").(string),
		TunnelSatellite: expandTunnelConfigSatellite(d),
		TunnelEnduser:   expandTunnelConfigEndUser(d),
		ClusterName:     clusterName,
		DisableSnat:     d.Get("disable_snat").(bool),
		SrcNATCIDRRange: d.Get("src_nat_cidr_range").(string),
		ApiKeyId:        d.Get("api_key_id").(string),
	}
	return at
}

func resourceAccessTierUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	clusterName, err := setAccessTierCluster(c, d)
	if err != nil {
		return diag.FromErr(err)
	}
	spec := atFromState(d, clusterName)
	updated, err := c.AccessTier.Update(d.Id(), spec)
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = updateLocalConfig(d, c, updated)
	d.SetId(updated.ID)
	return
}

func resourceAccessTierDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := resource.RetryContext(ctx, 180*time.Second, func() *resource.RetryError {
		err := c.AccessTier.Delete(d.Id())
		if err != nil {
			if err.Error() == "access_tier not found" {
				return nil
			}
			return resource.RetryableError(err)
		}
		return nil
	})
	if err != nil {
		return diag.Errorf("timed out deleting access tier: %s", d.Get("name").(string))
	}
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
	_, ok := d.GetOk("tunnel_private_domains")
	e := accesstier.AccessTierTunnelInfoPost{
		UDPPortNumber: 51820,
		DNSEnabled:    ok,
		CIDRs:         convertSchemaSetToStringSlice(d.Get("tunnel_cidrs").(*schema.Set)),
		Domains:       convertSchemaSetToStringSlice(d.Get("tunnel_private_domains").(*schema.Set)),
	}
	if reflect.DeepEqual(e, accesstier.AccessTierTunnelInfoPost{}) {
		return nil
	}
	return &e
}

func expandLogging(d *schema.ResourceData) (expanded *accesstier.LoggingParameters) {
	var statsd *bool
	statsdAddress := GetStringPtr(d, "statsd_address")
	if statsdAddress != nil {
		s := true
		statsd = &s
	}
	e := accesstier.LoggingParameters{
		ConsoleLogLevel: GetStringPtr(d, "console_log_level"),
		FileLogLevel:    GetStringPtr(d, "file_log_level"),
		FileLog:         GetBoolPtr(d, "file_log"),
		LogNum:          GetIntPtr(d, "log_num"),
		LogSize:         GetIntPtr(d, "log_size"),
		StatsD:          statsd,
		StatsDAddress:   GetStringPtr(d, "stats_d_address"),
	}
	return &e
}

func expandEventParameters(d *schema.ResourceData) (expanded *accesstier.EventParameters) {
	e := accesstier.EventParameters{
		CreditsLimiting: GetBoolPtr(d, "events_rate_limiting"),
		KeyLimiting:     GetBoolPtr(d, "event_key_rate_limiting"),
	}
	return &e
}

func expandHostedWebServices(d *schema.ResourceData) (expanded *accesstier.HostedWebServiceParameters) {
	e := accesstier.HostedWebServiceParameters{
		ForwardTrustCookie: GetBoolPtr(d, "forward_trust_cookie"),
		DisableHSTS:        GetBoolPtr(d, "enable_hsts"),
	}
	return &e
}

func expandInfrastructureService(d *schema.ResourceData) (expanded *accesstier.InfrastructureServiceParameters) {
	e := accesstier.InfrastructureServiceParameters{
		MaximumSessionTimeout: GetIntPtr(d, "infra_maximum_session_timeout"),
	}
	return &e
}

func expandDebugging(d *schema.ResourceData) (expanded *accesstier.DebuggingParameters) {
	e := accesstier.DebuggingParameters{
		HTTPBackendLog:      GetBoolPtr(d, "debug_http_backend_log"),
		VisibilityOnly:      GetBoolPtr(d, "debug_visibility_only"),
		ShieldTimeout:       GetIntPtr(d, "debug_shield_timeout"),
		KeepAlive:           GetBoolPtr(d, "debug_keep_alive"),
		KeepIdle:            GetIntPtr(d, "debug_keep_idle"),
		KeepInterval:        GetIntPtr(d, "debug_keep_interval"),
		KeepCount:           GetIntPtr(d, "debug_keep_count"),
		CPUProfile:          GetStringPtr(d, "debug_cpu_profile"),
		MemProfile:          GetBoolPtr(d, "debug_mem_profile"),
		HostOnly:            GetBoolPtr(d, "debug_host_only"),
		DisableDocker:       GetBoolPtr(d, "debug_disable_docker"),
		SendZeros:           GetBoolPtr(d, "debug_send_zeros"),
		Period:              GetIntPtr(d, "debug_period"),
		RequestLevelEvents:  GetBoolPtr(d, "debug_request_level_events"),
		AddressTransparency: GetBoolPtr(d, "debug_address_transparency"),
		UseRSA:              GetBoolPtr(d, "debug_use_rsa"),
		FullServerCertChain: GetBoolPtr(d, "debug_full_server_cert_chain"),
		CodeFlow:            GetBoolPtr(d, "debug_code_flow"),
		InactivityTimeout:   GetIntPtr(d, "debug_inactivity_timeout"),
		ClientTimeout:       GetIntPtr(d, "debug_client_timeout"),
	}
	return &e
}

func flattenDebuggingParameters(d *schema.ResourceData, atLocalConfig accesstier.AccessTierLocalConfig) (err error) {
	if isNil(atLocalConfig.DebuggingParameters) {
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
	err = d.Set("events_rate_limiting", atLocalConfig.EventParameters.CreditsLimiting)
	if err != nil {
		return
	}
	err = d.Set("event_key_rate_limiting", atLocalConfig.EventParameters.KeyLimiting)
	if err != nil {
		return
	}
	return
}

func flattenWebServices(d *schema.ResourceData, atLocalConfig accesstier.AccessTierLocalConfig) (err error) {
	if isNil(atLocalConfig.LoggingParameters) {
		return
	}
	err = d.Set("enable_hsts", atLocalConfig.HostedWebServiceParameters.DisableHSTS)
	if err != nil {
		return
	}
	err = d.Set("forward_trust_cookie", atLocalConfig.HostedWebServiceParameters.ForwardTrustCookie)
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
	err = d.Set("tunnel_private_domains", at.TunnelEnduser.Domains)
	if err != nil {
		return
	}
	err = d.Set("tunnel_cidrs", at.TunnelEnduser.CIDRs)
	if err != nil {
		return
	}
	return
}
