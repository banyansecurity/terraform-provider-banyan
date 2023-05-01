package banyan

import (
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"log"
	"strconv"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// This file contains expand / flatten functions which are common to infrastructure services and
// are used to abstract away complexity from the end user by populating the service struct using
// the minimum required variables

func resourceServiceInfraCommonRead(svc service.GetServiceSpec, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := d.Set("name", svc.ServiceName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", svc.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description_link", svc.CreateServiceSpec.Metadata.Tags.DescriptionLink)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("cluster", svc.ClusterName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	if svc.CreateServiceSpec.Metadata.Autorun {
		err = d.Set("autorun", svc.CreateServiceSpec.Metadata.Autorun)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	hostTagSelector := svc.CreateServiceSpec.Spec.Attributes.HostTagSelector[0]
	siteName := hostTagSelector["com.banyanops.hosttag.site_name"]
	accessTiers := strings.Split(siteName, "|")
	if accessTiers[0] == "*" {
		err = d.Set("access_tier", "")
	} else {
		err = d.Set("access_tier", accessTiers[0])
	}
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("connector", svc.CreateServiceSpec.Spec.Backend.ConnectorName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("domain", svc.CreateServiceSpec.Metadata.Tags.Domain)
	if err != nil {
		return diag.FromErr(err)
	}
	portVal := *svc.CreateServiceSpec.Metadata.Tags.Port
	portInt, _ := strconv.Atoi(portVal)
	err = d.Set("port", portInt)
	if err != nil {
		return diag.FromErr(err)
	}
	// TODO: refactor after service API refactor -- allows us to reuse this function for more services
	if !svc.CreateServiceSpec.Spec.Backend.HttpConnect {
		err = d.Set("backend_domain", svc.CreateServiceSpec.Spec.Backend.BackendTarget.Name)
		if err != nil {
			return diag.FromErr(err)
		}
		bpInt, _ := strconv.Atoi(svc.CreateServiceSpec.Spec.Backend.BackendTarget.Port)
		err = d.Set("backend_port", bpInt)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if svc.CreateServiceSpec.Metadata.Tags.AppListenPort != nil {
		clientPortVal := *svc.CreateServiceSpec.Metadata.Tags.AppListenPort
		clientPortInt, _ := strconv.Atoi(clientPortVal)
		err = d.Set("client_banyanproxy_listen_port", clientPortInt)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	err = d.Set("icon", svc.CreateServiceSpec.Metadata.Tags.Icon)
	if err != nil {
		return diag.FromErr(err)
	}
	availableInApp, err := strconv.ParseBool(*svc.CreateServiceSpec.Metadata.Tags.UserFacing)
	if err != nil {
		diag.FromErr(err)
	}
	err = d.Set("available_in_app", availableInApp)
	if err != nil {
		return diag.FromErr(err)
	}

	// set policy for service
	policy, err := c.Service.GetPolicyForService(svc.ServiceID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("policy", policy.ID)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Id())
	log.Printf("[INFO] Read service %s", d.Id())
	return
}

func expandInfraServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	attributes, err := expandInfraAttributes(d)
	if err != nil {
		return
	}
	spec = service.Spec{
		Attributes:   attributes,
		Backend:      expandInfraBackend(d),
		CertSettings: expandInfraCertSettings(d),
		HTTPSettings: expandInfraHTTPSettings(d),
		ClientCIDRs:  []service.ClientCIDRs{},
	}
	return
}

func expandInfraAttributes(d *schema.ResourceData) (attributes service.Attributes, err error) {
	hostTagSelector, err := buildHostTagSelector(d)
	if err != nil {
		return
	}
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

func expandInfraTarget(d *schema.ResourceData, httpConnect bool) (target service.BackendTarget) {
	// if http_connect, need to set Name to "" and Port to ""
	name := d.Get("backend_domain").(string)
	port := strconv.Itoa(d.Get("backend_port").(int))
	if httpConnect {
		name = ""
		port = ""
	}
	return service.BackendTarget{
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

func extractAutorun(d *schema.ResourceData) bool {
	autorun, exists := d.GetOk("autorun")
	if exists {
		return autorun.(bool)
	}
	return false
}
