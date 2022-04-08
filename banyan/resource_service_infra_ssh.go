package banyan

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/pkg/errors"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceInfraSsh() *schema.Resource {
	return &schema.Resource{
		Description:   "resourceServiceInfraSsh",
		CreateContext: resourceServiceInfraSshCreate,
		ReadContext:   resourceServiceInfraSshRead,
		UpdateContext: resourceServiceInfraSshUpdate,
		DeleteContext: resourceServiceInfraSshDelete,
		Schema:        resourceServiceInfraSshSchema,
	}
}

var resourceServiceInfraSshSchema = map[string]*schema.Schema{
	"id": {
		Type:        schema.TypeString,
		Description: "Id of the service",
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
		Default:     "resourceServiceInfraSsh",
	},
	"cluster": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Name of the cluster used for your deployment; for Global Edge set to \"global-edge\", for Private Edge set to \"cluster1\"",
		ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
	},
	"access_tier": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Name of the access_tier which will proxy requests to your service backend; set to \"\" if using Global Edge deployment'",
	},
	"connector": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Name of the connector which will proxy requests to your service backend; set to \"\" if using Private Edge deployment",
		Default:     "",
	},
	"domain": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "The external-facing network address for this service; ex. website.example.com",
	},
	"port": {
		Type:         schema.TypeInt,
		Optional:     true,
		Description:  "The external-facing port for this service",
		Default:      8443,
		ValidateFunc: validatePort(),
	},
	"backend_http_connect": {
		Type:        schema.TypeBool,
		Description: "Indicates to use HTTP Connect request to derive the backend target address.",
		Optional:    true,
		Default:     false,
	},
	"backend_domain": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using backend_http_connect",
	},
	"backend_port": {
		Type:         schema.TypeInt,
		Optional:     true,
		Description:  "The internal port where this service is hosted; set to 0 if using backend_http_connect",
		ValidateFunc: validatePort(),
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
}

func resourceServiceInfraSshCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating SSH service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	svc := expandSSHCreateService(d)

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create SSH service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] created SSH service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraSshRead(ctx, d, m)
}

func expandSSHCreateService(d *schema.ResourceData) (svc service.CreateService) {
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
	// set sshChainMode for backend_http_connect
	sshChainMode := d.Get("backend_http_connect").(bool)

	metadatatags = service.Tags{
		Template:         &template,
		UserFacing:       &userFacing,
		Protocol:         &protocol,
		Domain:           &domain,
		Port:             &port,
		Icon:             &icon,
		ServiceAppType:   &serviceAppType,
		SSHServiceType:   &sshServiceType,
		WriteSSHConfig:   &writeSSHConfig,
		SSHChainMode:     &sshChainMode,
		SSHHostDirective: &sshHostDirective,
		DescriptionLink:  &descriptionLink,
	}
	return
}

func resourceServiceInfraSshUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating SSH service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraSshCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated SSH service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraSshRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] reading SSH service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get SSH service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	d.Set("ssh_service_type", service.CreateServiceSpec.Metadata.Tags.SSHServiceType)
	d.Set("write_ssh_config", service.CreateServiceSpec.Metadata.Tags.WriteSSHConfig)
	d.Set("ssh_chain_mode", service.CreateServiceSpec.Metadata.Tags.SSHChainMode)
	d.Set("ssh_host_directive", service.CreateServiceSpec.Metadata.Tags.SSHHostDirective)
	diagnostics = resourceServiceInfraCommonRead(service, d, m)
	log.Printf("[SVC|RES|READ] read SSH service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraSshDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting SSH service %s : %s", d.Get("name"), d.Id())
	diagnostics = resourceServiceInfraCommonDelete(d, m)
	log.Printf("[SERVICE|RES|DELETE] deleted SSH service %s : %s", d.Get("name"), d.Id())
	return
}
