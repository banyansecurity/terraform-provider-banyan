package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"strconv"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceWeb() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of web services. For more information on web services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/hosted-websites/)",
		CreateContext: resourceServiceWebCreate,
		ReadContext:   resourceServiceWebRead,
		UpdateContext: resourceServiceWebUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        WebSchema(),
	}
}

func WebSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
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
		"access_tier": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the access_tier which will proxy requests to your service backend",
			ConflictsWith: []string{"connector"},
		},
		"connector": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the connector which will proxy requests to your service backend",
			ConflictsWith: []string{"access_tier"},
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
			Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using http_connect",
		},
		"backend_port": {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "The internal port where this service is hosted",
			Default:      443,
			ValidateFunc: validatePort(),
		},
		"backend_tls": {
			Type:        schema.TypeBool,
			Description: "Indicates whether the connection to the backend server uses TLS",
			Optional:    true,
			Default:     false,
		},
		"backend_tls_insecure": {
			Type:        schema.TypeBool,
			Description: "Indicates the connection to the backend should not validate the backend server TLS certificate",
			Optional:    true,
			Default:     false,
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
	}
	return
}

func resourceServiceWebCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := WebFromState(d)
	diagnostics = resourceServiceCreate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	return resourceServiceWebRead(ctx, d, m)
}

func resourceServiceWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[INFO] Reading service %s", d.Id())
	c := m.(*client.Holder)
	svc, err := c.Service.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	diagnostics = resourceServiceInfraCommonRead(svc, d, m)
	return
}

func resourceServiceWebUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	svc := WebFromState(d)
	diagnostics = resourceServiceUpdate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	diagnostics = resourceServiceWebRead(ctx, d, m)
	return
}

func WebFromState(d *schema.ResourceData) (svc service.CreateService) {
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
	attributes, err := expandWebAttributes(d)
	if err != nil {
		return
	}
	spec = service.Spec{
		Attributes:   attributes,
		Backend:      expandWebBackend(d),
		CertSettings: expandWebCertSettings(d),
		HTTPSettings: expandWebHTTPSettings(d),
		ClientCIDRs:  []service.ClientCIDRs{},
	}
	return
}

func expandWebAttributes(d *schema.ResourceData) (attributes service.Attributes, err error) {
	hostTagSelector, err := buildHostTagSelector(d)
	if err != nil {
		return
	}
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
