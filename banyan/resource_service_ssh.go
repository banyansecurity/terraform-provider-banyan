package banyan

import (
	"context"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceSsh() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of SSH services. For more information on SSH services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/ssh-servers/)",
		CreateContext: resourceServiceInfraSshCreate,
		ReadContext:   resourceServiceInfraSshRead,
		UpdateContext: resourceServiceInfraSshUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        SshSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func SshSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Description: "Id of the service in Banyan",
			Computed:    true,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the service; use lowercase alphanumeric characters or \"-\"",
			ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Description of the service",
		},
		"description_link": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Link shown to the end user of the banyan app for this service",
		},
		"autorun": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Autorun for the service, if set true service would autorun on the app",
		},
		"access_tier": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the access_tier which will proxy requests to your service backend",
			Default:       "",
			ConflictsWith: []string{"connector"},
		},
		"connector": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the connector which will proxy requests to your service backend",
			Default:       "",
			ConflictsWith: []string{"access_tier"},
		},
		"domain": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The external-facing network address for this service; ex. website.example.com",
		},
		"suppress_device_trust_verification": {
			Type:        schema.TypeBool,
			Description: "suppress_device_trust_verification disables Device Trust Verification for a service if set to true",
			Optional:    true,
			Default:     false,
		},
		"backend_domain": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using http_connect",
		},
		"backend_port": {
			Type:         schema.TypeInt,
			Required:     true,
			Description:  "The internal port where this service is hosted; set to 0 if using http_connect",
			ValidateFunc: validatePort(),
		},
		"port": {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "The external-facing port for this service",
			Default:      8443,
			ValidateFunc: validatePort(),
		},
		"available_in_app": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Whether this service is available in the app for users with permission to access this service",
		},
		"icon": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Name of the icon which will be displayed to the end user. The icon names can be found in the UI in the service config",
		},
		"disable_private_dns": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "By default, Private DNS Override will be set to true i.e disable_private_dns is false. On the device, the domain name will resolve over the service tunnel to the correct Access Tier's public IP address. If you turn off Private DNS Override i.e. disable_private_dns is set to true, you need to explicitly set a private DNS entry for the service domain name.",
		},
		"policy": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Policy ID to be attached to this service",
		},
		"cluster": {
			Type:        schema.TypeString,
			Description: "(Depreciated) Sets the cluster / shield for the service",
			Computed:    true,
			Optional:    true,
			Deprecated:  "This attribute is now configured automatically. This attribute will be removed in a future release of the provider.",
			ForceNew:    true,
		},
		"client_ssh_auth": {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Specifies which certificates - TRUSTCERT | SSHCERT | BOTH - should be used when the user connects to this service; default: TRUSTCERT",
			ValidateFunc: validation.StringInSlice([]string{"TRUSTCERT", "SSHCERT", "BOTH"}, false),
			Default:      "TRUSTCERT",
		},
		"client_ssh_host_directive": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Creates an entry in the SSH config file using the Host keyword. Wildcards are supported such as \"192.168.*.?\"; default: <service name>",
			Default:     "",
		},
		"backend_dns_override_for_domain": {
			Type:        schema.TypeString,
			Description: "Override DNS for service domain name with this value",
			Optional:    true,
		},
		"http_connect": {
			Type:        schema.TypeBool,
			Description: "Indicates to use HTTP Connect request to derive the backend target address.",
			Optional:    true,
			Default:     false,
		},
	}
	return s
}

func resourceServiceInfraSshCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := SshFromState(d)
	diagnostics = resourceServiceCreate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	return resourceServiceInfraSshRead(ctx, d, m)
}

func resourceServiceInfraSshRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	svc, err := c.Service.Get(id)
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("client_ssh_auth", svc.CreateServiceSpec.Metadata.Tags.SSHServiceType)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_ssh_host_directive", svc.CreateServiceSpec.Metadata.Tags.SSHHostDirective)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("http_connect", svc.CreateServiceSpec.Spec.Backend.HttpConnect)
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = resourceServiceInfraCommonRead(svc, d, m)
	return
}

func resourceServiceInfraSshUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	svc := SshFromState(d)
	return resourceServiceUpdate(svc, d, m)
}

func SshFromState(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandSSHMetatdataTags(d),
			Autorun:     expandAutorun(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}
	return
}

func expandSSHMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := strconv.FormatBool(d.Get("available_in_app").(bool))
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "SSH"
	descriptionLink := d.Get("description_link").(string)
	sshServiceType := d.Get("client_ssh_auth").(string)
	sshHostDirective := d.Get("client_ssh_host_directive").(string)
	writeSSHConfig := true
	sshChainMode := d.Get("http_connect").(bool)

	metadatatags = service.Tags{
		Template:         &template,
		UserFacing:       &userFacing,
		Protocol:         &protocol,
		Domain:           &domain,
		Port:             &port,
		Icon:             &icon,
		ServiceAppType:   &serviceAppType,
		DescriptionLink:  &descriptionLink,
		SSHServiceType:   &sshServiceType,
		WriteSSHConfig:   &writeSSHConfig,
		SSHChainMode:     &sshChainMode,
		SSHHostDirective: &sshHostDirective,
	}
	return
}
