package banyan

import (
	"fmt"
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
	if len(strings.TrimSpace(svc.CreateServiceSpec.Spec.Backend.ConnectorName)) > 0 {
		err = d.Set("connector", svc.CreateServiceSpec.Spec.Backend.ConnectorName)
		if err != nil {
			return diag.FromErr(err)
		}
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
		err = d.Set("client_banyanproxy_listen_port", clientPortVal)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	err = d.Set("icon", svc.CreateServiceSpec.Metadata.Tags.Icon)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("disable_private_dns", svc.CreateServiceSpec.Spec.DisablePrivateDns)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("suppress_device_trust_verification", svc.CreateServiceSpec.Spec.SuppressDeviceTrustVerification)
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

func flattenExemptions(paths service.ExemptedPaths) (flattened []interface{}, err error) {
	if !paths.Enabled {
		return
	}
	exemptions := make(map[string]interface{})
	exemptions["legacy_paths"] = paths.Paths
	if len(paths.Patterns) < 1 {
		flattened = append(flattened, exemptions)
		return
	}

	if len(paths.Patterns) != 1 {
		err = fmt.Errorf("more than one pattern not supported to import in terraform")
		return
	}
	exemptions["paths"] = paths.Patterns[0].Paths
	exemptions["source_cidrs"] = paths.Patterns[0].SourceCIDRs
	exemptions["mandatory_headers"] = paths.Patterns[0].MandatoryHeaders
	exemptions["http_methods"] = paths.Patterns[0].Methods

	var target []string
	var originHeader []string
	if len(paths.Patterns[0].Hosts) > 1 {
		err = fmt.Errorf("more than one hosts entries not supported to import in terraform")
		return
	}
	if len(paths.Patterns[0].Hosts) == 1 {
		target = paths.Patterns[0].Hosts[0].Target
		originHeader = paths.Patterns[0].Hosts[0].OriginHeader
	}
	exemptions["target_domain"] = target
	exemptions["origin_header"] = originHeader
	flattened = append(flattened, exemptions)
	return
}
func flattenCustomTLSCert(cert service.CustomTLSCert) (flattened []interface{}) {
	if !cert.Enabled {
		return
	}
	ctc := make(map[string]interface{})
	ctc["key_file"] = cert.KeyFile
	ctc["cert_file"] = cert.CertFile
	flattened = append(flattened, ctc)
	return
}
func flattenServiceAccountAccess(tokenLocation *service.TokenLocation) (flattened []interface{}) {
	if tokenLocation == nil {
		return
	}
	tl := make(map[string]interface{})
	tl["authorization_header"] = tokenLocation.AuthorizationHeader
	tl["custom_header"] = tokenLocation.CustomHeader
	tl["query_parameter"] = tokenLocation.QueryParam
	flattened = append(flattened, tl)
	return
}

func flattenAllowPatterns(httpConnect bool, patterns []service.BackendAllowPattern) (flattened []interface{}, err error) {
	// if http connect is false allow patterns should be empty
	if !httpConnect || len(patterns) == 0 {
		return
	}

	if !httpConnect && len(patterns) > 1 {
		err = fmt.Errorf("invalid configuiration, httpConnect is false and allow_patterns contains an entry")
		return
	}

	if len(patterns) > 1 {
		err = fmt.Errorf("more than one allow patterns not supported to import in terraform")
		return
	}
	allowPatterns := make(map[string]interface{})
	if len(patterns[0].CIDRs) > 0 {
		allowPatterns["cidrs"] = patterns[0].CIDRs
	}

	if len(patterns[0].Hostnames) > 0 {
		allowPatterns["hostnames"] = patterns[0].Hostnames
	}
	// if allow patterns is set return empty
	if len(allowPatterns) == 0 {
		return
	}
	flattened = append(flattened, allowPatterns)
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

func expandInfraBackend(d *schema.ResourceData) (backend service.Backend) {
	domain := d.Get("domain").(string)
	// build DNSOverrides
	DNSOverrides := map[string]string{}
	backendOverride, ok := d.GetOk("backend_dns_override_for_domain")
	if ok {
		DNSOverrides = map[string]string{
			domain: backendOverride.(string),
		}
	}
	httpConnect := false
	_, ok = d.GetOk("http_connect")
	if ok {
		httpConnect = d.Get("http_connect").(bool)
	}
	backend = service.Backend{
		BackendTarget:        expandInfraTarget(d, httpConnect),
		BackendDNSOverrides:  DNSOverrides,
		HttpConnect:          httpConnect,
		ConnectorName:        d.Get("connector").(string),
		BackendAllowPatterns: expandBackendAllowPatterns(d, httpConnect),
		BackendWhitelist:     []string{}, // deprecated
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

func expandAutorun(d *schema.ResourceData) bool {
	autorun, exists := d.GetOk("autorun")
	if exists {
		return autorun.(bool)
	}
	return false
}

func expandBackendAllowPatterns(d *schema.ResourceData, connect bool) (allowPatterns []service.BackendAllowPattern) {
	if !connect {
		return allowPatterns
	}
	allowPattern := service.BackendAllowPattern{}
	patterns, ok := d.GetOk("allow_patterns")
	if !ok {
		diag.Errorf("Unable to read allow_patterns")
	}

	cidrs, err := getStringListWithinSetForKey(patterns.(*schema.Set), "cidrs")
	if err != nil {
		diag.Errorf("Unable to read cidrs from allow_patterns")
	}
	if len(cidrs) > 1 {
		allowPattern.CIDRs = cidrs
	}
	hostnames, err := getStringListWithinSetForKey(patterns.(*schema.Set), "hostnames")
	if err != nil {
		diag.Errorf("Unable to read hostnames from allow_patterns")
	}
	if len(hostnames) > 1 {
		allowPattern.Hostnames = hostnames
	}
	return []service.BackendAllowPattern{allowPattern}
}
