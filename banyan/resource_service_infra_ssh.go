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
func resourceServiceInfraSsh() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of SSH services",
		CreateContext: resourceServiceInfraSshCreate,
		ReadContext:   resourceServiceInfraSshRead,
		UpdateContext: resourceServiceInfraSshUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        SshSchema(),
	}
}

func SshSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
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
		"client_banyanproxy_listen_port": {
			Type:        schema.TypeInt,
			Description: "For SSH, banyanproxy uses stdin instead of a local port",
			Computed:    true,
			Default:     nil,
		},
		"http_connect": {
			Type:        schema.TypeBool,
			Description: "Indicates to use HTTP Connect request to derive the backend target address.",
			Optional:    true,
			Default:     false,
		},
	}
	return combineSchema(s, resourceServiceInfraCommonSchema)
}

func resourceServiceInfraSshCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := SshFromState(d)
	return resourceServiceCreate(svc, d, m)
}

func resourceServiceInfraSshRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	svc, err := c.Service.Get(id)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_ssh_auth", svc.CreateServiceSpec.Metadata.Tags.SSHServiceType)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_ssh_host_directive", svc.CreateServiceSpec.Metadata.Tags.SSHHostDirective)
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = resourceServiceInfraCommonRead(svc, d)
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
	userFacing := "true"
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := ""
	serviceAppType := "SSH"
	descriptionLink := ""
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
