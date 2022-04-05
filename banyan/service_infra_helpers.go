package banyan

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
)

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
		FrontendAddresses: expandFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandInfraBackend(d *schema.ResourceData) (backend service.Backend) {
	backend = service.Backend{
		AllowPatterns: []service.BackendAllowPattern{},
		DNSOverrides:  convertEmptyInterfaceToStringMap(d.Get("backend.0.dns_overrides").(map[string]interface{})),
		ConnectorName: d.Get("backend.0.connector_name").(string),
		HTTPConnect:   false,
		Target:        expandTarget(d.Get("backend.0.target").([]interface{})),
		Whitelist:     []string{},
	}
	return
}

func expandInfraCertSettings(d *schema.ResourceData) (certSettings service.CertSettings) {
	dnsNames := []string{d.Get("domain").(string)}
	customTLSCert := service.CustomTLSCert{
		Enabled:  false,
		CertFile: "",
		KeyFile:  "",
	}
	letsEncrypt := false
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
		Letsencrypt:   letsEncrypt,
	}
	return
}

func flattenInfraServiceBackend(toFlatten service.Backend) (flattened []interface{}, diagnostics diag.Diagnostics) {
	v := make(map[string]interface{})
	v["target"], diagnostics = flattenServiceTarget(toFlatten.Target)
	v["connector_name"] = toFlatten.ConnectorName
	flattened = append(flattened, v)
	return
}

func flattenInfraServiceCertSettings(toFlatten service.CertSettings, domain string) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["dns_names"] = removeFromSlice(toFlatten.DNSNames, domain)
	flattened = append(flattened, v)
	return
}
