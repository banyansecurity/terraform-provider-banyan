package banyan

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceWeb() *schema.Resource {
	return &schema.Resource{
		Description:   "resourceServiceWeb",
		CreateContext: resourceServiceWebCreate,
		ReadContext:   resourceServiceWebRead,
		UpdateContext: resourceServiceWebUpdate,
		DeleteContext: resourceServiceWebDelete,
		Schema:        resourceServiceWebSchema,
	}
}

var resourceServiceWebSchema = map[string]*schema.Schema{
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
		Default:     "resourceServiceWeb",
	},
	"cluster": {
		Type:        schema.TypeString,
		Optional:    true,
		Default:     "global-edge",
		Description: "Name of the cluster used for your deployment; for Global Edge set to \"global-edge\", for Private Edge set to \"cluster1\"",
		ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
	},
	"access_tier": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Name of the access_tier which will proxy requests to your service backend; set to \"\" if using Global Edge deployment'",
		Default:     "",
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
		Default:      443,
		ValidateFunc: validatePort(),
	},
	"letsencrypt": {
		Type:        schema.TypeBool,
		Description: "Use a Public CA-issued server certificate instead of a Private CA-issued one",
		Optional:    true,
		Default:     false,
	},
	"backend_domain": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using backend_http_connect",
	},
	"backend_port": {
		Type:         schema.TypeInt,
		Required:     true,
		Description:  "The internal port where this service is hosted",
		ValidateFunc: validatePort(),
	},
	"backend_tls": {
		Type:        schema.TypeBool,
		Description: "Indicates whether the connection to the backend server uses TLS.",
		Optional:    true,
		Default:     false,
	},
	"backend_tls_insecure": {
		Type:        schema.TypeBool,
		Description: "Indicates the connection to the backend should not validate the backend server TLS certficate",
		Optional:    true,
		Default:     false,
	},
}

func resourceServiceWebCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating web service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	svc := expandWebCreateService(d)

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create web service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created web service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceWebRead(ctx, d, m)
}

func resourceServiceWebUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating web service %s : %s", d.Get("name"), d.Id())
	resourceServiceWebCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated web service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] Reading web service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get web servicewith id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	err = d.Set("name", service.ServiceName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("description", service.Description)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("cluster", service.ClusterName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	hostTagSelector := service.CreateServiceSpec.Spec.Attributes.HostTagSelector[0]
	siteName := hostTagSelector["com.banyanops.hosttag.site_name"]
	accessTiers := strings.Split(siteName, "|")
	err = d.Set("access_tier", accessTiers[0])
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("connector", service.CreateServiceSpec.Spec.Backend.ConnectorName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("domain", service.CreateServiceSpec.Metadata.Tags.Domain)
	if err != nil {
		return diag.FromErr(err)
	}
	portVal := *service.CreateServiceSpec.Metadata.Tags.Port
	portInt, _ := strconv.Atoi(portVal)
	err = d.Set("port", portInt)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("letsencrypt", service.CreateServiceSpec.Spec.CertSettings.Letsencrypt)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_domain", service.CreateServiceSpec.Spec.Backend.Target.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	bpInt, _ := strconv.Atoi(service.CreateServiceSpec.Spec.Backend.Target.Port)
	err = d.Set("backend_port", bpInt)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_tls", service.CreateServiceSpec.Spec.Backend.Target.TLS)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_tls_insecure", service.CreateServiceSpec.Spec.Backend.Target.TLSInsecure)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(id)
	return
}

func resourceServiceWebDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting web service with id: %q \n", d.Id())
	client := m.(*client.ClientHolder)
	diagnostics = resourceServiceDetachPolicy(d, m)
	if diagnostics.HasError() {
		return
	}
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	log.Printf("[SERVICE|RES|DELETE] deleted web service with id: %q \n", d.Id())
	return
}

func expandWebCreateService(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandWebMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandWebServiceSpec(d),
	}
	return
}

func expandWebMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "WEB_USER"
	userFacing := "true"
	protocol := "https"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := ""
	serviceAppType := "WEB"
	descriptionLink := ""

	metadatatags = service.Tags{
		Template:        &template,
		UserFacing:      &userFacing,
		Protocol:        &protocol,
		Domain:          &domain,
		Port:            &port,
		Icon:            &icon,
		ServiceAppType:  &serviceAppType,
		DescriptionLink: &descriptionLink,
	}
	return
}

func expandWebServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	spec = service.Spec{
		Attributes:   expandWebAttributes(d),
		Backend:      expandWebBackend(d),
		CertSettings: expandWebCertSettings(d),
		HTTPSettings: expandWebHTTPSettings(d),
		ClientCIDRs:  []service.ClientCIDRs{},
	}
	return
}

func expandWebAttributes(d *schema.ResourceData) (attributes service.Attributes) {
	// if connector is set, ensure access_tier is *
	accessTier := d.Get("access_tier").(string)
	connector := d.Get("connector").(string)
	if connector != "" {
		accessTier = "*"
	}

	// build HostTagSelector from access_tier
	var hostTagSelector []map[string]string
	siteNameSelector := map[string]string{"com.banyanops.hosttag.site_name": accessTier}
	hostTagSelector = append(hostTagSelector, siteNameSelector)

	attributes = service.Attributes{
		TLSSNI:            []string{d.Get("domain").(string)},
		FrontendAddresses: expandWebFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandWebFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	frontendAddresses = []service.FrontendAddress{
		{
			CIDR: "",
			Port: strconv.Itoa(d.Get("port").(int)),
		},
	}
	return
}

func expandWebBackend(d *schema.ResourceData) (backend service.Backend) {
	backend = service.Backend{
		Target:        expandWebTarget(d),
		ConnectorName: d.Get("connector").(string),
		DNSOverrides:  map[string]string{},
		Whitelist:     []string{},
	}
	return
}

func expandWebTarget(d *schema.ResourceData) (target service.Target) {
	return service.Target{
		Name:        d.Get("backend_domain").(string),
		Port:        strconv.Itoa(d.Get("backend_port").(int)),
		TLS:         d.Get("backend_tls").(bool),
		TLSInsecure: d.Get("backend_tls_insecure").(bool),
	}
}

func expandWebCertSettings(d *schema.ResourceData) (certSettings service.CertSettings) {
	certSettings = service.CertSettings{
		DNSNames:    []string{d.Get("domain").(string)},
		Letsencrypt: d.Get("letsencrypt").(bool),
	}
	return
}

func expandWebHTTPSettings(d *schema.ResourceData) (httpSettings service.HTTPSettings) {
	httpSettings = service.HTTPSettings{
		Enabled:         true,
		OIDCSettings:    expandWebOIDCSettings(d),
		ExemptedPaths:   expandWebExemptedPaths(d),
		Headers:         map[string]string{},
		HTTPHealthCheck: expandWebHTTPHealthCheck(),
	}
	return
}

func expandWebOIDCSettings(d *schema.ResourceData) (oidcSettings service.OIDCSettings) {
	oidcSettings = service.OIDCSettings{
		Enabled:           true,
		ServiceDomainName: fmt.Sprintf("https://%s", d.Get("domain").(string)),
	}
	return
}

func expandWebExemptedPaths(d *schema.ResourceData) (exemptedPaths service.ExemptedPaths) {
	exemptedPaths = service.ExemptedPaths{
		Enabled: false,
	}
	return
}

func expandWebHTTPHealthCheck() (httpHealthCheck service.HTTPHealthCheck) {
	httpHealthCheck = service.HTTPHealthCheck{
		Enabled:     false,
		Addresses:   nil,
		Method:      "",
		Path:        "",
		UserAgent:   "",
		FromAddress: []string{},
		HTTPS:       false,
	}
	return
}
