package banyan

import (
	"strconv"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// This file contains expand / flatten functions which are common to infrastructure services and
// are used to abstract away complexity from the end user by populating the service struct using
// the minimum required variables

var resourceServiceInfraCommonSchema = map[string]*schema.Schema{
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
	"client_banyanproxy_listen_port": {
		Type:         schema.TypeInt,
		Optional:     true,
		Description:  "Local listen port to be used by client proxy; if not specified, a random local port will be used",
		ValidateFunc: validatePort(),
	},
}

func resourceServiceInfraCommonRead(service service.GetServiceSpec, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := d.Set("name", service.ServiceName)
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
	err = d.Set("backend_http_connect", service.CreateServiceSpec.Spec.Backend.HTTPConnect)
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
	if service.CreateServiceSpec.Metadata.Tags.AppListenPort != nil {
		clientPortVal := *service.CreateServiceSpec.Metadata.Tags.AppListenPort
		clientPortInt, _ := strconv.Atoi(clientPortVal)
		err = d.Set("client_banyanproxy_listen_port", clientPortInt)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	d.SetId(d.Id())
	return
}

func resourceServiceInfraCommonDelete(d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.ClientHolder)
	diagnostics = resourceServiceDetachPolicy(d, m)
	if diagnostics.HasError() {
		return
	}
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	return
}

func expandInfraServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	spec = service.Spec{
		Attributes:   expandInfraAttributes(d),
		Backend:      expandInfraBackend(d),
		CertSettings: expandInfraCertSettings(d),
		HTTPSettings: expandInfraHTTPSettings(d),
		ClientCIDRs:  []service.ClientCIDRs{},
	}
	return
}

func expandInfraAttributes(d *schema.ResourceData) (attributes service.Attributes) {
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
		FrontendAddresses: expandInfraFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandInfraFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	frontendAddresses = []service.FrontendAddress{
		{
			CIDR: "",
			Port: strconv.Itoa(d.Get("port").(int)),
		},
	}
	return
}

func expandInfraBackend(d *schema.ResourceData) (backend service.Backend) {
	http_connect := d.Get("backend_http_connect").(bool)
	var allow_patterns []service.BackendAllowPattern
	if http_connect {
		allow_patterns = []service.BackendAllowPattern{{}}
	}

	backend = service.Backend{
		Target:        expandInfraTarget(d),
		HTTPConnect:   d.Get("backend_http_connect").(bool),
		ConnectorName: d.Get("connector").(string),
		DNSOverrides:  map[string]string{},
		AllowPatterns: allow_patterns,
		Whitelist:     []string{}, // deprecated
	}
	return
}

func expandInfraTarget(d *schema.ResourceData) (target service.Target) {
	// if http_connect, need to set Name and Port to ""
	name := d.Get("backend_domain").(string)
	port := strconv.Itoa(d.Get("backend_port").(int))
	http_connect := d.Get("backend_http_connect").(bool)
	if http_connect {
		name = ""
		port = ""
	}
	return service.Target{
		Name:              name,
		Port:              port,
		TLS:               false,
		TLSInsecure:       false,
		ClientCertificate: false,
	}
}

func expandInfraCertSettings(d *schema.ResourceData) (certSettings service.CertSettings) {
	certSettings = service.CertSettings{
		DNSNames:    []string{d.Get("domain").(string)},
		Letsencrypt: false,
	}
	return
}

func expandInfraHTTPSettings(d *schema.ResourceData) (httpSettings service.HTTPSettings) {
	httpSettings = service.HTTPSettings{
		Enabled:         false,
		OIDCSettings:    expandInfraOIDCSettings(d),
		ExemptedPaths:   expandInfraExemptedPaths(d),
		Headers:         map[string]string{},
		HTTPHealthCheck: expandInfraHTTPHealthCheck(),
	}
	return
}

func expandInfraOIDCSettings(d *schema.ResourceData) (oidcSettings service.OIDCSettings) {
	oidcSettings = service.OIDCSettings{
		Enabled:           false,
		ServiceDomainName: "",
	}
	return
}

func expandInfraExemptedPaths(d *schema.ResourceData) (exemptedPaths service.ExemptedPaths) {
	exemptedPaths = service.ExemptedPaths{
		Enabled:  false,
		Patterns: expandInfraPatterns(d),
	}
	return
}

func expandInfraPatterns(d *schema.ResourceData) (patterns []service.Pattern) {
	patterns = []service.Pattern{
		{
			Hosts:            expandInfraHosts(d),
			Methods:          []string{},
			Paths:            []string{},
			MandatoryHeaders: []string{},
		},
	}
	return
}

func expandInfraHosts(d *schema.ResourceData) (hosts []service.Host) {
	hosts = []service.Host{
		{
			OriginHeader: []string{},
			Target:       []string{},
		},
	}
	return
}

func expandInfraHTTPHealthCheck() (httpHealthCheck service.HTTPHealthCheck) {
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
