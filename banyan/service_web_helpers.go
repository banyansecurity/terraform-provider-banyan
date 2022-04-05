package banyan

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// This file contains expand / flatten functions which are common to web services and
// are used to abstract away complexity from the end user by populating the service struct using
// the minimum required variables

func expandWebServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	spec = service.Spec{
		Attributes:   expandAttributes(d),
		Backend:      expandBackend(d),
		CertSettings: expandCertSettings(d),
		HTTPSettings: expandHTTPSettings(d.Get("http_settings").([]interface{})),
		ClientCIDRs:  expandClientCIDRs(d.Get("client_cidrs").([]interface{})),
		TagSlice:     expandTagSlice(d.Get("tag_slice").([]interface{})),
	}
	return
}

func flattenWebServiceCertSettings(toFlatten service.CertSettings, domain string) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["custom_tls_cert"] = flattenServiceCustomTLSCert(toFlatten.CustomTLSCert)
	v["dns_names"] = removeFromSlice(toFlatten.DNSNames, domain)
	v["letsencrypt"] = toFlatten.Letsencrypt
	flattened = append(flattened, v)
	return
}
