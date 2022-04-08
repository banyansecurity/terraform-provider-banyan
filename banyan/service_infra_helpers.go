package banyan

import (
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
	"strings"
)

// This file contains expand / flatten functions which are common to infrastructure services and
// are used to abstract away complexity from the end user by populating the service struct using
// the minimum required variables

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
	hostTagSelector := service.CreateServiceSpec.Spec.HostTagSelector[0]
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
	err = d.Set("icon", service.CreateServiceSpec.Metadata.Tags.Icon)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description_link", service.CreateServiceSpec.Metadata.Tags.DescriptionLink)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Id())
	return
}

func resourceServiceInfraCommonDelete(d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.ClientHolder)
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
		TagSlice:     nil,
	}
	return
}

func expandInfraAttributes(d *schema.ResourceData) (attributes service.Attributes) {
	var tlsSNI []string
	tlsSNI = append(tlsSNI, d.Get("domain").(string))
	// build HostTagSelector from access_tier
	var hostTagSelector []map[string]string
	siteNameSelector := map[string]string{"com.banyanops.hosttag.site_name": d.Get("access_tier").(string)}
	hostTagSelector = append(hostTagSelector, siteNameSelector)
	attributes = service.Attributes{
		TLSSNI:            tlsSNI,
		FrontendAddresses: expandInfraFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandInfraBackend(d *schema.ResourceData) (backend service.Backend) {
	backend = service.Backend{
		AllowPatterns: nil,
		DNSOverrides:  map[string]string{},
		ConnectorName: d.Get("connector").(string),
		HTTPConnect:   d.Get("backend_http_connect").(bool),
		Target:        expandInfraTarget(d),
		Whitelist:     []string{},
	}
	return
}

func expandInfraTarget(d *schema.ResourceData) (target service.Target) {
	return service.Target{
		Name:              d.Get("backend_domain").(string),
		Port:              strconv.Itoa(d.Get("backend_port").(int)),
		TLS:               false,
		TLSInsecure:       false,
		ClientCertificate: false,
	}
}

func expandInfraFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	portInt := d.Get("port").(int)
	frontendAddresses = append(
		frontendAddresses,
		service.FrontendAddress{
			CIDR: "",
			Port: strconv.Itoa(portInt),
		},
	)
	return
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
		Patterns: nil,
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
