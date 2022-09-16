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
		Schema:        buildResourceServiceInfraSshSchema(),
	}
}

func buildResourceServiceInfraSshSchema() (schemaSsh map[string]*schema.Schema) {
	schemaSsh = map[string]*schema.Schema{
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
	}
	for key, val := range resourceServiceInfraCommonSchema {
		if schemaSsh[key] == nil {
			schemaSsh[key] = val
		}
	}
	return
}

func resourceServiceInfraSshCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating SSH service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
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
	// do not set allowUserOverride

	sshServiceType := d.Get("client_ssh_auth").(string)
	sshHostDirective := d.Get("client_ssh_host_directive").(string)
	writeSSHConfig := true
	// set sshChainMode for http_connect
	sshChainMode := d.Get("http_connect").(bool)

	metadatatags = service.Tags{
		Template:        &template,
		UserFacing:      &userFacing,
		Protocol:        &protocol,
		Domain:          &domain,
		Port:            &port,
		Icon:            &icon,
		ServiceAppType:  &serviceAppType,
		DescriptionLink: &descriptionLink,

		SSHServiceType:   &sshServiceType,
		WriteSSHConfig:   &writeSSHConfig,
		SSHChainMode:     &sshChainMode,
		SSHHostDirective: &sshHostDirective,
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
	client := m.(*client.Holder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get SSH service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	err = d.Set("client_ssh_auth", service.CreateServiceSpec.Metadata.Tags.SSHServiceType)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_ssh_host_directive", service.CreateServiceSpec.Metadata.Tags.SSHHostDirective)
	if err != nil {
		return diag.FromErr(err)
	}
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
