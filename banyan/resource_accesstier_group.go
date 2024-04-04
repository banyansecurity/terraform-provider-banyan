package banyan

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstiergroup"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceAccessTierGroup() *schema.Resource {
	return &schema.Resource{
		Description:   "The access tier group resource allows for configuration of the access tier group API object. ",
		CreateContext: resourceAccessTierGroupCreate,
		ReadContext:   resourceAccessTierGroupRead,
		DeleteContext: resourceAccessTierGroupDelete,
		UpdateContext: resourceAccessTierGroupUpdate,
		Schema:        AccessTierGroupSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func AccessTierGroupSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the access tier group in Banyan",
			ForceNew:    true,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the access tier group",
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Description of access tier group",
		},
		"cluster": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Cluster / shield name in Banyan",
		},
		"dns_search_domains": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "",
		},
		"cidrs": {
			Type:        schema.TypeSet,
			Required:    true,
			Description: "CIDR range",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"dns_enabled": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enable DNS for service tunnels (needed to work properly with both private and public targets)",
		},
		"udp_port_number": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "UDP port",
		},
		"keepalive": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "Keepalive",
		},
		"domains": {
			Type:        schema.TypeSet,
			Required:    true,
			Description: "Any internal domains that can only be resolved on your internal network’s private DNS",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"shared_fqdn": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Shared FQDN",
		},
		"attach_access_tier_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Access tier IDs to attach to access tier group",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"detach_access_tier_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Access tier IDs to detach from access tier group",
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

func resourceAccessTierGroupCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	atg, err := c.AccessTierGroup.Create(atgFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(atg.ID)

	attachIDs := convertSchemaSetToStringSlice(d.Get("attach_access_tier_ids").(*schema.Set))
	if len(attachIDs) != 0 {
		err = attachAccessTiers(c, d.Get("id").(string), attachIDs)
		if err != nil {
			return
		}
	}

	return
}

func resourceAccessTierGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	key, err := c.AccessTierGroup.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	d.SetId(key.ID)
	err = d.Set("name", key.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", key.Description)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("cluster", key.ClusterName)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("cidrs", key.TunnelConfig.CIDRs)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("domains", key.TunnelConfig.Domains)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("dns_enabled", key.TunnelConfig.DNSEnabled)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("shared_fqdn", key.TunnelConfig.SharedFQDN)
	if err != nil {
		return diag.FromErr(err)
	}

	var advancedSettings accesstier.AccessTierLocalConfig
	err = json.Unmarshal([]byte(key.AdvancedSettings), &advancedSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	err = flattenLoggingParameters(d, advancedSettings)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenEventParameters(d, advancedSettings)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenWebServices(d, advancedSettings)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenInfrastructureServiceParameters(d, advancedSettings)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenDebuggingParameters(d, advancedSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceAccessTierGroupUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	_, err := c.AccessTierGroup.Update(d.Id(), atgFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}

	attachIDs := convertSchemaSetToStringSlice(d.Get("attach_access_tier_ids").(*schema.Set))
	if len(attachIDs) != 0 {
		err = attachAccessTiers(c, d.Get("id").(string), attachIDs)
		if err != nil {
			return
		}
	}

	detachIDs := convertSchemaSetToStringSlice(d.Get("detach_access_tier_ids").(*schema.Set))
	if len(detachIDs) != 0 {
		err = detachAccessTiers(c, d.Get("id").(string), detachIDs)
		if err != nil {
			return
		}
	}

	return
}

func resourceAccessTierGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.AccessTierGroup.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId("")
	return
}

// creates an access tier group from the terraform state
func atgFromState(d *schema.ResourceData) accesstiergroup.AccessTierGroupPost {
	at := accesstiergroup.AccessTierGroupPost{
		Name:             d.Get("name").(string),
		Description:      d.Get("description").(string),
		SharedFQDN:       d.Get("shared_fqdn").(string),
		ClusterName:      d.Get("cluster").(string),
		TunnelConfig:     setATGTunnelConfigEndUserRequest(d),
		AdvancedSettings: exapandAdvancedSettings(d),
	}
	return at
}

func setATGTunnelConfigEndUserRequest(d *schema.ResourceData) (expanded *accesstier.AccessTierTunnelInfoPost) {
	e := accesstier.AccessTierTunnelInfoPost{
		UDPPortNumber: d.Get("udp_port_number").(int),
		DNSEnabled:    d.Get("dns_enabled").(bool),
		CIDRs:         convertSchemaSetToStringSlice(d.Get("cidrs").(*schema.Set)),
		Domains:       convertSchemaSetToStringSlice(d.Get("domains").(*schema.Set)),
	}
	if reflect.DeepEqual(e, accesstier.AccessTierTunnelInfoPost{}) {
		return nil
	}
	return &e
}

func attachAccessTiers(c *client.Holder, atgID string, atIDs []string) (err error) {

	attachReqBody := accesstiergroup.AccessTierList{
		AccessTierIDs: atIDs,
	}
	_, err = c.AccessTierGroup.AttachAccessTiers(atgID, attachReqBody)
	if err != nil {
		return
	}

	return
}

func detachAccessTiers(c *client.Holder, atgID string, atIDs []string) (err error) {
	attachReqBody := accesstiergroup.AccessTierList{
		AccessTierIDs: atIDs,
	}
	_, err = c.AccessTierGroup.DetachAccessTiers(atgID, attachReqBody)
	if err != nil {
		return
	}

	return
}

func exapandAdvancedSettings(d *schema.ResourceData) accesstier.AccessTierLocalConfig {
	lc := accesstier.AccessTierLocalConfig{
		LoggingParameters:               expandLogging(d),
		EventParameters:                 expandEventParameters(d),
		HostedWebServiceParameters:      expandHostedWebServices(d),
		InfrastructureServiceParameters: expandInfrastructureService(d),
		DebuggingParameters:             expandDebugging(d),
	}

	return lc
}
