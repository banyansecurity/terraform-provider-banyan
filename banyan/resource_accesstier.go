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
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Public address of the access tier",
			},
			"cluster": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Cluster the access tier belongs to",
				ForceNew:    true,
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
			"tunnel_connector": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "Settings for connectors attached to this access tier",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"port": {
							Type:         schema.TypeInt,
							Optional:     true,
							Description:  "UDP for for connectors to this access tier to utilize",
							Default:      51821,
							ValidateFunc: validatePort(),
						},
					},
				},
			},
			"tunnel_enduser": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "Settings for end users attached to this access tier",
				//TODO: check this
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"dns_search_domains": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "",
						},
						"port": {
							Type:         schema.TypeInt,
							Optional:     true,
							Description:  "UDP for for end users to this access tier to utilize",
							Default:      51820,
							ValidateFunc: validatePort(),
						},
						"dns_enabled": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "",
							Default:     false,
						},
						"cidrs": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"domains": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"logging": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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
					},
				},
			},
			"events": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_event_credits_limiting": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Enable or disable Netagent access event rate limiting",
						},
						"access_event_credits_per_interval": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Number of credits to assign after an interval",
						},
						"access_event_credits_interval": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "After this interval, assign number of credits per the above",
						},
						"access_event_credits_max": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Maximum number of credits to assign a Netagent. One event consumes one credit.",
						},
						"access_event_key_limiting": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Enable or disable Netagent access key event rate limiting",
						},
						"access_event_key_expiration": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "After this interval, another access key event may be generated",
						},
					},
				},
			},
			"hosted_web_services": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "Netagent's handling of backend hosted web services",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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
					},
				},
			},
			"infrastructure_services": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "Netagent's handling of backend infrastructure services",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"maximum_session_timeout": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "",
						},
					},
				},
			},
			"denial_of_service_protection": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "Parameters related to denial of service protection",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"bad_actor": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Enable or disable DoS protection",
						},
						"infraction_count": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Number of unauthorized requests before an offending IP address is jailed",
						},
						"sentence_time": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Jail interval after which bad actor is freed",
						},
					},
				},
			},
			"debugging": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"http_backend_log": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Verbose logging for HTTP backend traffic",
						},
						"visibility_only": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Enable or disable visibility mode. If on, Netagent will not do policy enforcement on inbound traffic",
						},
						"shield_timeout": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "If Shield is not available, policies will be treated as if they are permissive. Zero means this is disabled.",
						},
						"keep_alive": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Enable TCP keepalive messages for TCP sockets handled by Netagent",
						},
						"keep_idle": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Idle time before sending a TCP keepalive",
						},
						"keep_interval": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Time between consecutive TCP keepalive messages",
						},
						"keep_count": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Number of missing TCP keepalive acknowledgements before closing connection",
						},
						"cpu_profile": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Output file for CPU profiling; may impact performance. If empty, this is disabled",
						},
						"mem_profile": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Output file for memory profiling; may impact performance. If empty, this is disabled",
						},
						"host_only": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Host only mode",
						},
						"disable_docker": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Disable Docker monitoring",
						},
						"send_zeros": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Send all-zero data points to Shield",
						},
						"period": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Interval for reporting statistics",
						},
						"request_level_events": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Generate access events at the request level",
						},
						"address_transparency": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Provide client address transparency",
						},
						"use_rsa": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Netagent will generate RSA instead of ECDSA keys",
						},
						"full_server_cert_chain": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Include non-root (intermediate) CA certs during TLS handshakes",
						},
						"code_flow": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Enable or disable OpenID Connect",
						},
						"inactivity_timeout": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "HTTP inactivity timeout",
						},
						"client_timeout": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Client identification timeout",
						},
					},
				},
			},
			"miscellaneous": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "General parameters that don't fit in a specific category",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"access_tier": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Enable or disable access tier mode. If disabled, then uses host agent mode",
						},
						"host_tags": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Arbitrary key-value pairs used for attribute matching on Netagent",
							Elem: &schema.Schema{
								Type: schema.TypeMap,
								Elem: &schema.Schema{Type: schema.TypeString},
							},
						},
						"listen_port": {
							Type:         schema.TypeInt,
							Optional:     true,
							Description:  "TCP listen port on Netagent host for proxying incoming connections",
							ValidateFunc: validation.IntBetween(1024, 65535),
						},
						"listen_port_health": {
							Type:         schema.TypeInt,
							Optional:     true,
							Description:  "TCP listen port on Netagent host for health checks",
							ValidateFunc: validation.IntBetween(1024, 65535),
						},
						"https_proxy": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Establish control connection to Shield using HTTP CONNECT proxy. Overrides HTTPS_PROXY environment variable",
						},
						"public_ip_source": {
							Type:         schema.TypeInt,
							Optional:     true,
							Description:  "Configures how Netagent will determine its public IP",
							ValidateFunc: validation.StringInSlice([]string{"AWS", "GCE", "default", "none"}, false),
						},
						"cpu_limit": {
							Type:         schema.TypeInt,
							Optional:     true,
							Description:  "Max percentage of CPU core usage",
							ValidateFunc: validation.IntBetween(1, 100),
						},
						"user_mode_tunnel": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Whether WireGuard should use a userspace or kernel space module",
						},
						"enduser_tunnel_cidr": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Used for source NAT support",
						},
					},
				},
			},
			"service_discovery": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Optional:    true,
				Description: "Parameters related to service discovery",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"service_discovery_enable": {
							Type:        schema.TypeBool,
							Optional:    true,
							Description: "Enable or disable DNS and conntrack logging",
						},
						"service_discovery_msg_limit": {
							Type:         schema.TypeInt,
							Optional:     true,
							Description:  "Message threshold for batch processing",
							ValidateFunc: validation.IntInSlice([]int{100, 1000, 5000}),
						},
						"service_discovery_msg_timeout": {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "Timeout value for service discovery batch processing",
						},
					},
				},
			},
		},
	}
}

func resourceAccessTierCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("creating access tier %s : %s", d.Get("name"), d.Id())
	c := m.(*client.Holder)

	aT := accesstier.AccessTierPost{
		Name:            d.Get("name").(string),
		Address:         d.Get("address").(string),
		TunnelSatellite: expandTunnelConfigSatellite(d.Get("tunnel_connector").([]interface{})),
		TunnelEnduser:   expandTunnelConfigEndUser(d.Get("tunnel_enduser").([]interface{})),
		ClusterName:     d.Get("cluster").(string),
		DisableSnat:     d.Get("disable_snat").(bool),
		SrcNATCIDRRange: d.Get("src_nat_cidr_range").(string),
		ApiKeyId:        d.Get("api_key_id").(string),
	}
	createdAccessTier, err := c.AccessTier.Create(aT)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new access tier"))
	}
	createdLocalConfig, err := c.AccessTier.GetLocalConfig(createdAccessTier.Name)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't retrieve local config for access tier"))
	}

	lC := accesstier.AccessTierLocalConfig{
		BaseParameters: &accesstier.BaseParameters{
			ShieldAddress: createdLocalConfig.ShieldAddress,
			SiteAddress:   createdLocalConfig.SiteAddress,
		},
		LoggingParameters:               expandLogging(d),
		EventParameters:                 expandEventParameters(d),
		HostedWebServiceParameters:      expandHostedWebServices(d),
		InfrastructureServiceParameters: expandInfrastructureService(d),
		DoSProtectionParameters:         expandDoSProtection(d),
		DebuggingParameters:             expandDebugging(d),
		MiscellaneousParameters:         expandMiscellaneous(d),
		ServiceDiscoveryParameters:      expandServiceDiscovery(d),
		Spec:                            nil,
	}
	_, err = c.AccessTier.UpdateLocalConfig(createdAccessTier.Name, lC)
	if err != nil {
		return diag.FromErr(errors.Errorf("failed to update local configuration for %s", createdAccessTier.Name))
	}
	log.Printf("created access tier %s : %s", createdAccessTier.Name, d.Id())
	diagnostics = resourceAccessTierRead(ctx, d, m)
	d.SetId(createdAccessTier.ID)
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
	err = d.Set("name", at.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("address", at.Address)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("cluster", at.ClusterName)
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
	if !isNil(at.TunnelSatellite) {
		err = d.Set("tunnel_connector", flattenTunnelConfigSatellite(*at.TunnelSatellite))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(at.TunnelEnduser) {
		err = d.Set("tunnel_enduser", flattenTunnelConfigEndUser(*at.TunnelEnduser))
		if err != nil {
			return diag.FromErr(err)
		}
	}

	// Now get the local config
	atLocalConfig, err := client.AccessTier.GetLocalConfig(at.Name)

	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't read access tier"))
	}
	if !isNil(atLocalConfig.LoggingParameters) {
		err = d.Set("logging", flattenLoggingParameters(*atLocalConfig.LoggingParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(atLocalConfig.EventParameters) {
		err = d.Set("events", flattenEventParameters(*atLocalConfig.EventParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(atLocalConfig.HostedWebServiceParameters) {
		err = d.Set("hosted_web_services", flattenEventParameters(*atLocalConfig.EventParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(atLocalConfig.InfrastructureServiceParameters) {
		err = d.Set("infrastructure_services", flattenInfrastructureServiceParameters(*atLocalConfig.InfrastructureServiceParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(atLocalConfig.DoSProtectionParameters) {
		err = d.Set("infrastructure_services", flattenDoSProtectionParameters(*atLocalConfig.DoSProtectionParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(atLocalConfig.DebuggingParameters) {
		err = d.Set("infrastructure_services", flattenDebuggingParameters(*atLocalConfig.DebuggingParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(atLocalConfig.MiscellaneousParameters) {
		err = d.Set("infrastructure_services", flattenMiscellaneousParameters(*atLocalConfig.MiscellaneousParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if !isNil(atLocalConfig.ServiceDiscoveryParameters) {
		err = d.Set("infrastructure_services", flattenServiceDiscoveryParameters(*atLocalConfig.ServiceDiscoveryParameters))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	log.Printf("read access tier %s : %s", d.Get("name"), d.Id())
	return
}

func resourceAccessTierUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("updating access tier %s : %s", d.Get("name"), d.Id())
	c := m.(*client.Holder)
	aT := accesstier.AccessTierPost{
		Name:            d.Get("name").(string),
		Address:         d.Get("address").(string),
		TunnelSatellite: expandTunnelConfigSatellite(d.Get("tunnel_connector").([]interface{})),
		TunnelEnduser:   expandTunnelConfigEndUser(d.Get("tunnel_enduser").([]interface{})),
		ClusterName:     d.Get("cluster").(string),
		DisableSnat:     d.Get("disable_snat").(bool),
		SrcNATCIDRRange: d.Get("src_nat_cidr_range").(string),
		ApiKeyId:        d.Get("api_key_id").(string),
	}
	updatedAccessTier, err := c.AccessTier.Update(d.Id(), aT)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't update access tier"))
	}
	updatedLocalConfig, err := c.AccessTier.GetLocalConfig(updatedAccessTier.Name)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't retrieve local config for access tier"))
	}

	lC := accesstier.AccessTierLocalConfig{
		BaseParameters: &accesstier.BaseParameters{
			ShieldAddress: updatedLocalConfig.ShieldAddress,
			SiteAddress:   updatedLocalConfig.SiteAddress,
		},
		LoggingParameters:               expandLogging(d),
		EventParameters:                 expandEventParameters(d),
		HostedWebServiceParameters:      expandHostedWebServices(d),
		InfrastructureServiceParameters: expandInfrastructureService(d),
		DoSProtectionParameters:         expandDoSProtection(d),
		DebuggingParameters:             expandDebugging(d),
		MiscellaneousParameters:         expandMiscellaneous(d),
		ServiceDiscoveryParameters:      expandServiceDiscovery(d),
		Spec:                            nil,
	}
	updatedLocalConfig, err = c.AccessTier.UpdateLocalConfig(d.Id(), lC)
	if err != nil {
		return diag.FromErr(errors.Errorf("couldn't update local configuration for %s", aT.Name))
	}
	log.Printf("updated access tier %s : %s", aT.Name, d.Id())
	d.SetId(updatedAccessTier.ID)
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

func expandTunnelConfigSatellite(toFlatten []interface{}) (flattened *accesstier.AccessTierTunnelInfo) {
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	tunnelConfig := accesstier.AccessTierTunnelInfo{
		UDPPortNumber: int64(tc["port"].(int)),
	}
	return &tunnelConfig
}

func expandTunnelConfigEndUser(toFlatten []interface{}) (flattened *accesstier.AccessTierTunnelInfo) {
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	tunnelConfig := accesstier.AccessTierTunnelInfo{
		DNSSearchDomains: tc["dns_search_domains"].(string),
		UDPPortNumber:    int64(tc["port"].(int)),
		DNSEnabled:       tc["dns_enabled"].(bool),
		Keepalive:        50,
		CIDRs:            convertSchemaSetToStringSlice(tc["cidrs"].(*schema.Set)),
		Domains:          convertSchemaSetToStringSlice(tc["domains"].(*schema.Set)),
	}
	return &tunnelConfig
}

func expandLogging(d *schema.ResourceData) (expanded *accesstier.LoggingParameters) {
	_, ok := d.GetOk("logging")
	if !ok {
		return
	}
	toFlatten := d.Get("logging").([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	ConsoleLogLevel := tc["console_log_level"].(string)
	FileLogLevel := tc["file_log_level"].(string)
	FileLog := tc["file_log"].(bool)
	LogNum := tc["log_num"].(int)
	LogSize := tc["log_size"].(int)
	StatsD := tc["statsd"].(bool)
	StatsDAddress := tc["statsd_address"].(string)

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
	_, ok := d.GetOk("events")
	if !ok {
		return
	}
	toFlatten := d.Get("events").([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	CreditsLimiting := tc["access_event_credits_limiting"].(bool)
	CreditsPerInterval := tc["access_event_credits_per_interval"].(int)
	CreditsInterval := tc["access_event_credits_interval"].(int)
	CreditsMax := tc["access_event_credits_max"].(int)
	KeyLimiting := tc["access_event_key_limiting"].(bool)
	KeyExpiration := tc["access_event_key_expiration"].(int)

	e := accesstier.EventParameters{
		CreditsLimiting:    &CreditsLimiting,
		CreditsPerInterval: &CreditsPerInterval,
		CreditsInterval:    &CreditsInterval,
		CreditsMax:         &CreditsMax,
		KeyLimiting:        &KeyLimiting,
		KeyExpiration:      &KeyExpiration,
	}
	return &e
}

func expandHostedWebServices(d *schema.ResourceData) (expanded *accesstier.HostedWebServiceParameters) {
	_, ok := d.GetOk("hosted_web_services")
	if !ok {
		return
	}
	toFlatten := d.Get("hosted_web_services").([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	ForwardTrustCookie := tc["forward_trust_cookie"].(bool)
	DisableHSTS := tc["disable_hsts"].(bool)

	e := accesstier.HostedWebServiceParameters{
		ForwardTrustCookie: &ForwardTrustCookie,
		DisableHSTS:        &DisableHSTS,
	}
	return &e
}

func expandInfrastructureService(d *schema.ResourceData) (expanded *accesstier.InfrastructureServiceParameters) {
	_, ok := d.GetOk("infrastructure_services")
	if !ok {
		return
	}
	toFlatten := d.Get("infrastructure_services").([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	MaximumSessionTimeout := tc["maximum_session_timeout"].(int)

	e := accesstier.InfrastructureServiceParameters{
		MaximumSessionTimeout: &MaximumSessionTimeout,
	}
	return &e
}

func expandDoSProtection(d *schema.ResourceData) (expanded *accesstier.DoSProtectionParameters) {
	_, ok := d.GetOk("denial_of_service_protection")
	if !ok {
		return
	}
	toFlatten := d.Get("denial_of_service_protection").([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	BadActor := tc["bad_actor"].(bool)
	InfractionCount := tc["infraction_count"].(int)
	SentenceTime := tc["sentence_time"].(int)

	e := accesstier.DoSProtectionParameters{
		BadActor:        &BadActor,
		InfractionCount: &InfractionCount,
		SentenceTime:    &SentenceTime,
	}
	return &e
}

func expandDebugging(d *schema.ResourceData) (expanded *accesstier.DebuggingParameters) {
	debugging, ok := d.GetOk("debugging")
	if !ok {
		return
	}
	toFlatten := debugging.([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	HTTPBackendLog := tc["http_backend_log"].(bool)
	VisibilityOnly := tc["visibility_only"].(bool)
	ShieldTimeout := tc["shield_timeout"].(int)
	KeepAlive := tc["keep_alive"].(bool)
	KeepIdle := tc["keep_idle"].(int)
	KeepInterval := tc["keep_interval"].(int)
	KeepCount := tc["keep_count"].(int)
	CPUProfile := tc["cpu_profile"].(string)
	MemProfile := tc["mem_profile"].(bool)
	HostOnly := tc["host_only"].(bool)
	DisableDocker := tc["disable_docker"].(bool)
	SendZeros := tc["send_zeros"].(bool)
	Period := tc["period"].(int)
	RequestLevelEvents := tc["request_level_events"].(bool)
	AddressTransparency := tc["address_transparency"].(bool)
	UseRSA := tc["use_rsa"].(bool)
	FullServerCertChain := tc["full_server_cert_chain"].(bool)
	CodeFlow := tc["code_flow"].(bool)
	InactivityTimeout := tc["inactivity_timeout"].(int)
	ClientTimeout := tc["client_timeout"].(int)

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

func expandMiscellaneous(d *schema.ResourceData) (expanded *accesstier.MiscellaneousParameters) {
	_, ok := d.GetOk("miscellaneous")
	if !ok {
		return
	}
	toFlatten := d.Get("miscellaneous").([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	AccessTier := tc["access_tier"].(bool)
	ListenPort := tc["listen_port"].(int)
	ListenPortHealth := tc["listen_port_health"].(int)
	HTTPSProxy := tc["https_proxy"].(string)
	PublicIPSource := tc["public_ip_source"].(string)
	CPULimit := tc["cpu_limit"].(int)
	UserModeTunnel := tc["user_mode_tunnel"].(bool)
	EnduserTunnelCIDR := tc["enduser_tunnel_cidr"].(string)

	e := accesstier.MiscellaneousParameters{
		AccessTier:        &AccessTier,
		HostTags:          tc["host_tags"].(map[string]string),
		ListenPort:        &ListenPort,
		ListenPortHealth:  &ListenPortHealth,
		HTTPSProxy:        &HTTPSProxy,
		PublicIPSource:    &PublicIPSource,
		CPULimit:          &CPULimit,
		UserModeTunnel:    &UserModeTunnel,
		EnduserTunnelCIDR: &EnduserTunnelCIDR,
	}
	return &e
}

func expandServiceDiscovery(d *schema.ResourceData) (expanded *accesstier.ServiceDiscoveryParameters) {
	_, ok := d.GetOk("service_discovery")
	if !ok {
		return
	}
	toFlatten := d.Get("service_discovery").([]interface{})
	if len(toFlatten) == 0 {
		return
	}
	tc := toFlatten[0].(map[string]interface{})
	ServiceDiscoveryEnable := tc["service_discovery_enable"].(bool)
	ServiceDiscoveryMsgLimit := tc["service_discovery_msg_limit"].(int)
	ServiceDiscoveryMsgTimeout := tc["service_discovery_msg_timeout"].(int)

	e := accesstier.ServiceDiscoveryParameters{
		ServiceDiscoveryEnable:     &ServiceDiscoveryEnable,
		ServiceDiscoveryMsgLimit:   &ServiceDiscoveryMsgLimit,
		ServiceDiscoveryMsgTimeout: &ServiceDiscoveryMsgTimeout,
	}
	return &e
}

func flattenServiceDiscoveryParameters(toFlatten accesstier.ServiceDiscoveryParameters) (flattened []interface{}) {
	flattened = append(flattened, map[string]interface{}{
		"service_discovery_enable":      toFlatten.ServiceDiscoveryEnable,
		"service_discovery_msg_limit":   toFlatten.ServiceDiscoveryMsgLimit,
		"service_discovery_msg_timeout": toFlatten.ServiceDiscoveryMsgTimeout,
	})
	return
}

func flattenMiscellaneousParameters(toFlatten accesstier.MiscellaneousParameters) (flattened []interface{}) {
	flattened = append(flattened, map[string]interface{}{
		"access_tier":        toFlatten.AccessTier,
		"host_tags":          toFlatten.HostTags,
		"listen_port":        toFlatten.ListenPort,
		"listen_port_health": toFlatten.ListenPortHealth,
		"https_proxy":        toFlatten.HTTPSProxy,
		"public_ip_source":   toFlatten.PublicIPSource,
		"cpu_limit":          toFlatten.CPULimit,
		"user_mode_tunnel":   toFlatten.UserModeTunnel,
		"EnduserTunnelCIDR":  toFlatten.EnduserTunnelCIDR,
	})
	return
}

func flattenDebuggingParameters(toFlatten accesstier.DebuggingParameters) (flattened []interface{}) {
	flattened = append(flattened, map[string]interface{}{
		"http_backend_log":       toFlatten.HTTPBackendLog,
		"visibility_only":        toFlatten.VisibilityOnly,
		"shield_timeout":         toFlatten.ShieldTimeout,
		"keep_alive":             toFlatten.KeepAlive,
		"keep_idle":              toFlatten.KeepIdle,
		"keep_interval":          toFlatten.KeepInterval,
		"keep_count":             toFlatten.KeepCount,
		"cpu_profile":            toFlatten.CPUProfile,
		"mem_profile":            toFlatten.MemProfile,
		"host_only":              toFlatten.HostOnly,
		"disable_docker":         toFlatten.DisableDocker,
		"send_zeros":             toFlatten.SendZeros,
		"period":                 toFlatten.Period,
		"request_level_events":   toFlatten.RequestLevelEvents,
		"address_transparency":   toFlatten.AddressTransparency,
		"use_rsa":                toFlatten.UseRSA,
		"full_server_cert_chain": toFlatten.FullServerCertChain,
		"code_flow":              toFlatten.CodeFlow,
		"inactivity_timeout":     toFlatten.InactivityTimeout,
		"client_timeout":         toFlatten.ClientTimeout,
	})
	return
}

func flattenDoSProtectionParameters(toFlatten accesstier.DoSProtectionParameters) (flattened []interface{}) {
	flattened = append(flattened, map[string]interface{}{
		"bad_actor":        toFlatten.BadActor,
		"infraction_count": toFlatten.InfractionCount,
		"sentence_time":    toFlatten.SentenceTime,
	})
	return
}

func flattenInfrastructureServiceParameters(toFlatten accesstier.InfrastructureServiceParameters) (flattened []interface{}) {
	flattened = append(flattened, map[string]interface{}{
		"maximum_session_timeout": toFlatten.MaximumSessionTimeout,
	})
	return
}

func flattenEventParameters(toFlatten accesstier.EventParameters) (flattened []interface{}) {
	flattened = append(flattened, map[string]interface{}{
		"access_event_credits_limiting":     toFlatten.CreditsLimiting,
		"access_event_credits_per_interval": toFlatten.CreditsPerInterval,
		"access_event_credits_interval":     toFlatten.CreditsPerInterval,
		"access_event_credits_max":          toFlatten.CreditsMax,
		"access_event_key_limiting":         toFlatten.KeyLimiting,
		"access_event_key_expiration":       toFlatten.KeyExpiration,
	})
	return
}

func flattenLoggingParameters(toFlatten accesstier.LoggingParameters) (flattened []interface{}) {
	flattened = append(flattened, map[string]interface{}{
		"console_log_level": toFlatten.ConsoleLogLevel,
		"file_log_level":    toFlatten.FileLogLevel,
		"file_log":          toFlatten.FileLog,
		"log_num":           toFlatten.LogNum,
		"log_size":          toFlatten.LogSize,
		"statsd":            toFlatten.StatsD,
		"statsd_address":    toFlatten.StatsDAddress,
	})
	return
}

func flattenTunnelConfigSatellite(toFlatten accesstier.AccessTierTunnelInfo) (flattened []interface{}) {
	f := make(map[string]interface{})
	f["port"] = toFlatten.UDPPortNumber
	return append(flattened, f)
}

func flattenTunnelConfigEndUser(toFlatten accesstier.AccessTierTunnelInfo) (flattened []interface{}) {
	f := make(map[string]interface{})
	f["dns_search_domains"] = toFlatten.DNSSearchDomains
	f["port"] = toFlatten.UDPPortNumber
	f["dns_enabled"] = toFlatten.DNSEnabled
	f["cidrs"] = toFlatten.CIDRs
	f["domains"] = toFlatten.Domains
	return append(flattened, f)
}
