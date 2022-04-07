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
	err = d.Set("access_tiers", accessTiers)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	var metadataTagUserFacing bool
	metadataTagUserFacingPtr := service.CreateServiceSpec.Metadata.Tags.UserFacing
	if metadataTagUserFacingPtr != nil {
		metadataTagUserFacing, err = strconv.ParseBool(*service.CreateServiceSpec.Metadata.Tags.UserFacing)
		if err != nil {
			diagnostics = diag.FromErr(err)
			return
		}
	}
	err = d.Set("connector", service.CreateServiceSpec.Spec.Backend.ConnectorName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("user_facing", metadataTagUserFacing)
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
	tlsSNI := removeFromSlice(service.CreateServiceSpec.Spec.Attributes.TLSSNI, *service.CreateServiceSpec.Metadata.Tags.Domain)
	err = d.Set("tls_sni", tlsSNI)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("cert_settings", flattenInfraServiceCertSettings(service.CreateServiceSpec.Spec.CertSettings, *service.CreateServiceSpec.Metadata.Tags.Domain))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Id())
	return
}

func resourceServiceInfraCommonReadBackendPort(service service.GetServiceSpec, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	backendPortStr := service.CreateServiceSpec.Spec.Backend.Target.Port
	backendPort, err := strconv.Atoi(backendPortStr)
	if err != nil {
		diagnostics = diag.Errorf("Could not convert BackendTarget.spec.backend.target.port to int %v", backendPortStr)
		return
	}
	err = d.Set("backend_port", backendPort)
	if err != nil {
		return diag.FromErr(err)
	}
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
		HTTPSettings: service.HTTPSettings{},
		ClientCIDRs:  []service.ClientCIDRs{},
		TagSlice:     service.TagSlice{},
	}
	return
}

func expandInfraAttributes(d *schema.ResourceData) (attributes service.Attributes) {
	var tlsSNI []string
	additionalTlsSni := convertSchemaSetToStringSlice(d.Get("tls_sni").(*schema.Set))
	for _, s := range additionalTlsSni {
		tlsSNI = append(tlsSNI, s)
	}
	tlsSNI = append(tlsSNI, d.Get("domain").(string))
	tlsSNI = removeDuplicateStr(tlsSNI)

	// build HostTagSelector from access_tiers
	var hostTagSelector []map[string]string
	accessTiers := d.Get("access_tiers").(*schema.Set)
	accessTiersSlice := convertSchemaSetToStringSlice(accessTiers)
	siteNamesString := strings.Join(accessTiersSlice, "|")
	siteNameSelector := map[string]string{"com.banyanops.hosttag.site_name": siteNamesString}
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
		AllowPatterns: expandAllowPatterns(d.Get("allow_patterns").([]interface{})),
		DNSOverrides:  convertEmptyInterfaceToStringMap(d.Get("dns_overrides").(map[string]interface{})),
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
	dnsNames := []string{d.Get("domain").(string)}
	customTLSCert := service.CustomTLSCert{
		Enabled:  false,
		CertFile: "",
		KeyFile:  "",
	}
	m := d.Get("cert_settings").([]interface{})
	if len(m) >= 1 {
		itemMap := m[0].(map[string]interface{})
		for _, d := range convertSchemaSetToStringSlice(itemMap["dns_names"].(*schema.Set)) {
			dnsNames = append(dnsNames, d)
		}
		dnsNames = removeDuplicateStr(dnsNames)
		customTLSCert = service.CustomTLSCert{}
	}

	certSettings = service.CertSettings{
		DNSNames:      dnsNames,
		CustomTLSCert: customTLSCert,
		Letsencrypt:   false,
	}
	return
}

func flattenInfraServiceCertSettings(toFlatten service.CertSettings, domain string) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["dns_names"] = removeFromSlice(toFlatten.DNSNames, domain)
	flattened = append(flattened, v)
	return
}
