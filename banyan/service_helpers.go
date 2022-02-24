package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"math"
	"net"
	"strconv"
)

func expandMetatdataTags(m []interface{}) (metadatatags service.Tags) {
	tags := m[0].(map[string]interface{})
	template := tags["template"].(string)
	userFacingMetadataTag := tags["user_facing"].(bool)
	userFacing := strconv.FormatBool(userFacingMetadataTag)
	protocol := tags["protocol"].(string)
	domain := tags["domain"].(string)
	portInt := tags["port"].(int)
	port := strconv.Itoa(portInt)
	icon := tags["icon"].(string)
	serviceAppType := tags["service_app_type"].(string)
	enforcementMode := tags["enforcement_mode"].(string)
	sshServiceType := tags["ssh_service_type"].(string)
	writeSSHConfig := tags["write_ssh_config"].(bool)
	alp := tags["app_listen_port"].(int)
	appListenPort := strconv.Itoa(alp)
	banyanProxyMode := tags["banyan_proxy_mode"].(string)
	allowUserOverride := tags["allow_user_override"].(bool)
	sshChainMode := tags["ssh_chain_mode"].(bool)
	sshHostDirective := tags["ssh_host_directive"].(string)
	kubeClusterName := tags["kube_cluster_name"].(string)
	kubeCaKey := tags["kube_ca_key"].(string)
	descriptionLink := tags["description_link"].(string)
	incd := tags["include_domains"].([]interface{})
	includeDomains := make([]string, 0)
	for _, includeDomainItem := range incd {
		includeDomains = append(includeDomains, includeDomainItem.(string))
	}
	metadatatags = service.Tags{
		Template:          &template,
		UserFacing:        &userFacing,
		Protocol:          &protocol,
		Domain:            &domain,
		Port:              &port,
		Icon:              &icon,
		ServiceAppType:    &serviceAppType,
		EnforcementMode:   &enforcementMode,
		SSHServiceType:    &sshServiceType,
		WriteSSHConfig:    &writeSSHConfig,
		BanyanProxyMode:   &banyanProxyMode,
		AppListenPort:     &appListenPort,
		AllowUserOverride: &allowUserOverride,
		SSHChainMode:      &sshChainMode,
		SSHHostDirective:  &sshHostDirective,
		KubeClusterName:   &kubeClusterName,
		KubeCaKey:         &kubeCaKey,
		DescriptionLink:   &descriptionLink,
		IncludeDomains:    &includeDomains,
	}
	return
}

func expandServiceSpec(d *schema.ResourceData) (spec service.Spec, err error) {
	spec = service.Spec{
		Attributes:   expandAttributes(d),
		Backend:      expandBackend(d),
		CertSettings: expandCertSettings(d),
		ClientCIDRs:  expandClientCIDRs(d.Get("client_cidrs").([]interface{})),
		HTTPSettings: expandHTTPSettings(d),
		TagSlice:     expandTagSlice(d.Get("tag_slice").([]interface{})),
	}
	return
}

func expandAttributes(d *schema.ResourceData) (attributes service.Attributes) {
	var tlsSNI []string
	tlsSNIs := d.Get("tls_sni").([]interface{})
	for _, i := range tlsSNIs {
		tlsSNI = append(tlsSNI, i.(string))
	}

	var hostTagSelector []map[string]string
	hostTagSelectors := d.Get("host_tag_selector").([]interface{})
	for _, i := range hostTagSelectors {
		hostTagSelectorMap, _ := convertEmptyInterfaceToStringMap(i)
		hostTagSelector = append(hostTagSelector, hostTagSelectorMap)
	}

	attributes = service.Attributes{
		TLSSNI:            tlsSNI,
		FrontendAddresses: expandFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	frontEndAddressList := d.Get("frontend_address").([]interface{})
	for _, frontEndAddressItem := range frontEndAddressList {
		frontEndAddressItemMap := frontEndAddressItem.(map[string]interface{})
		frontendAddresses = append(
			frontendAddresses,
			service.FrontendAddress{
				CIDR: frontEndAddressItemMap["cidr"].(string),
				Port: frontEndAddressItemMap["port"].(string),
			},
		)
	}
	return
}

func expandBackend(d *schema.ResourceData) (backend service.Backend) {
	var whitelist []string
	whitelistSet := d.Get("whitelist").(*schema.Set)
	for _, whitelistItem := range whitelistSet.List() {
		whitelist = append(whitelist, whitelistItem.(string))
	}

	dnsOverridesMap := d.Get("dns_overrides").(map[string]interface{})
	dnsOverrides, _ := convertEmptyInterfaceToStringMap(dnsOverridesMap)

	backend = service.Backend{
		AllowPatterns: expandAllowPatterns(d.Get("backend_allow_patterns").([]interface{})),
		DNSOverrides:  dnsOverrides,
		ConnectorName: d.Get("connector_name").(string),
		HTTPConnect:   d.Get("http_connect").(bool),
		Target:        expandTarget(d.Get("target").([]interface{})),
		Whitelist:     whitelist,
	}
	return
}

func expandAllowPatterns(m []interface{}) (allowPatterns []service.BackendAllowPattern) {
	for _, backendAllowPatternItem := range m {
		item := backendAllowPatternItem.(map[string]interface{})

		var hostnames []string
		hostnamesSet := item["hostnames"].(*schema.Set)
		for _, hostname := range hostnamesSet.List() {
			hostnames = append(hostnames, hostname.(string))
		}

		var cidrs []string
		cidrsSet := item["cidrs"].(*schema.Set)
		for _, cidr := range cidrsSet.List() {
			cidrs = append(cidrs, cidr.(string))
		}

		allowPatterns = append(allowPatterns, service.BackendAllowPattern{
			Hostnames: hostnames,
			CIDRs:     cidrs,
			Ports:     expandBackendAllowPorts(item["ports"].([]interface{})),
		})
	}
	return
}

func expandBackendAllowPorts(m []interface{}) (backendAllowPorts service.BackendAllowPorts) {
	itemMap := m[0].(map[string]interface{})
	var portList []int
	portListSet := itemMap["port_list"].(*schema.Set)
	for _, port := range portListSet.List() {
		portList = append(portList, port.(int))
	}
	backendAllowPorts = service.BackendAllowPorts{
		PortList:   portList,
		PortRanges: expandPortRanges(itemMap["port_range"].([]interface{})),
	}
	return
}

func expandPortRanges(m []interface{}) (portRanges []service.PortRange) {
	for _, portRangeItem := range m {
		portRangeItemMap := portRangeItem.(map[string]interface{})
		newPortRange := service.PortRange{
			Min: portRangeItemMap["min"].(int),
			Max: portRangeItemMap["max"].(int),
		}
		portRanges = append(portRanges, newPortRange)
	}
	return
}

func expandTarget(m []interface{}) (target service.Target) {
	targetItemMap := m[0].(map[string]interface{})
	return service.Target{
		Name:              targetItemMap["name"].(string),
		Port:              strconv.Itoa(targetItemMap["port"].(int)),
		TLS:               targetItemMap["tls"].(bool),
		TLSInsecure:       targetItemMap["tls_insecure"].(bool),
		ClientCertificate: targetItemMap["client_certificate"].(bool),
	}
}

func expandCertSettings(d *schema.ResourceData) (certSettings service.CertSettings) {
	m := d.Get("cert_settings").([]interface{})
	itemMap := m[0].(map[string]interface{})

	var dnsNames []string
	dnsNamesSet := itemMap["dns_names"].(*schema.Set)
	for _, dnsNamesItem := range dnsNamesSet.List() {
		dnsNames = append(dnsNames, dnsNamesItem.(string))
	}

	certSettings = service.CertSettings{
		DNSNames:      dnsNames,
		CustomTLSCert: expandCustomTLSCert(itemMap["custom_tls_cert"].([]interface{})),
		Letsencrypt:   itemMap["letsencrypt"].(bool),
	}
	return
}

func expandClientCIDRs(m []interface{}) (clientCIDRs []service.ClientCIDRs) {
	for _, clientCIDR := range m {
		clientCIDRItemMap := clientCIDR.(map[string]interface{})

		var hostTagSelector []map[string]string
		hostTagSelectorList := clientCIDRItemMap["host_tag_selector"].([]interface{})
		for _, hostTagSelectorItem := range hostTagSelectorList {
			hostTagSelectorItemMap, _ := convertEmptyInterfaceToStringMap(hostTagSelectorItem)
			hostTagSelector = append(hostTagSelector, hostTagSelectorItemMap)
		}

		var clusters []string
		clustersSet := clientCIDRItemMap["clusters"].(*schema.Set)
		for _, clustersItem := range clustersSet.List() {
			clusters = append(clusters, clustersItem.(string))
		}

		clientCIDRs = append(clientCIDRs, service.ClientCIDRs{
			Addresses:       expandCIDRAddress(clientCIDRItemMap["address"].([]interface{})),
			HostTagSelector: hostTagSelector,
			Clusters:        clusters,
		})
	}
	return
}

func expandCIDRAddress(m []interface{}) (addresses []service.CIDRAddress) {
	for _, item := range m {
		itemMap := item.(map[string]interface{})
		addresses = append(addresses, service.CIDRAddress{
			CIDR:  itemMap["cidr"].(string),
			Ports: itemMap["ports"].(string),
		})
	}
	return
}

func expandHTTPSettings(d *schema.ResourceData) (httpSettings service.HTTPSettings) {
	tokenLoc := expandTokenLoc(d.Get("token_loc").([]interface{}))

	headersMap := d.Get("headers").(map[string]interface{})
	headers, _ := convertInterfaceMapToStringMap(headersMap)

	httpSettings = service.HTTPSettings{
		Enabled:         d.Get("http_settings_enabled").(bool),
		OIDCSettings:    expandOIDCSettings(d.Get("oidc_settings").([]interface{})),
		HTTPHealthCheck: expandHTTPHealthCheck(d.Get("http_health_check").([]interface{})),
		// will be deprecated from api
		HTTPRedirect:  service.HTTPRedirect{},
		ExemptedPaths: expandExemptedPaths(d),
		Headers:       headers,
		TokenLoc:      &tokenLoc,
	}
	return
}

func expandCustomTLSCert(m []interface{}) (customTLSCert service.CustomTLSCert) {
	itemMap := m[0].(map[string]interface{})
	customTLSCert = service.CustomTLSCert{
		Enabled:  itemMap["enabled"].(bool),
		CertFile: itemMap["cert_file"].(string),
		KeyFile:  itemMap["key_file"].(string),
	}
	return
}

func expandTagSlice(m []interface{}) (tagSlice []service.ResourceTag) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		tagSlice = append(tagSlice, service.ResourceTag{
			ID:        data["id"].(string),
			OrgID:     data["org_id"].(string),
			ServiceID: data["service_id"].(string),
			Name:      data["name"].(string),
			Value:     data["value"].(string),
		})
	}
	return
}

func expandOIDCSettings(m []interface{}) (oidcSettings service.OIDCSettings) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})

	trustCallBacksMap := itemMap["trust_callbacks"].(map[string]interface{})
	trustCallBacks, _ := convertInterfaceMapToStringMap(trustCallBacksMap)

	oidcSettings = service.OIDCSettings{
		Enabled:                         itemMap["enabled"].(bool),
		ServiceDomainName:               itemMap["service_domain_name"].(string),
		PostAuthRedirectPath:            itemMap["post_auth_redirect_path"].(string),
		APIPath:                         itemMap["api_path"].(string),
		TrustCallBacks:                  trustCallBacks,
		SuppressDeviceTrustVerification: itemMap["suppress_device_trust_verification"].(bool),
	}
	return
}

func expandHTTPHealthCheck(m []interface{}) (httpHealthCheck service.HTTPHealthCheck) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})

	var addresses []string
	itemMapSet := itemMap["addresses"].(*schema.Set)
	for _, addressesItem := range itemMapSet.List() {
		addresses = append(addresses, addressesItem.(string))
	}

	var fromAddress []string
	fromAddressSet := itemMap["from_address"].(*schema.Set)
	for _, fromAddressItem := range fromAddressSet.List() {
		fromAddress = append(fromAddress, fromAddressItem.(string))
	}

	httpHealthCheck = service.HTTPHealthCheck{
		Enabled:     itemMap["enabled"].(bool),
		Addresses:   addresses,
		Method:      itemMap["method"].(string),
		Path:        itemMap["path"].(string),
		UserAgent:   itemMap["user_agent"].(string),
		FromAddress: fromAddress,
		HTTPS:       itemMap["https"].(bool),
	}
	return
}

func expandExemptedPaths(d *schema.ResourceData) (exemptedPaths service.ExemptedPaths) {
	m := d.Get("exempted_paths").([]interface{})
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	patterns := expandPatterns(itemMap["patterns"].([]interface{}))
	exemptedPaths = service.ExemptedPaths{
		Enabled: itemMap["enabled"].(bool),
		// will be deprecated from API
		Paths:    make([]string, 0),
		Patterns: patterns,
	}
	return
}

func expandPatterns(m []interface{}) (patterns []service.Pattern) {
	for _, raw := range m {
		data := raw.(map[string]interface{})

		hosts := expandHosts(data["hosts"].([]interface{}))

		var paths []string
		pathsSet := data["paths"].(*schema.Set)
		for _, pathItem := range pathsSet.List() {
			paths = append(paths, pathItem.(string))
		}

		var sourceCIRDs []string
		sourceCIRDsSet := data["source_cidrs"].(*schema.Set)
		for _, sourceCIRDsItem := range sourceCIRDsSet.List() {
			sourceCIRDs = append(sourceCIRDs, sourceCIRDsItem.(string))
		}

		var methods []string
		methodsSet := data["methods"].(*schema.Set)
		for _, methodsItem := range methodsSet.List() {
			methods = append(methods, methodsItem.(string))
		}

		var mandatoryHeaders []string
		mandatoryHeadersSet := data["mandatory_headers"].(*schema.Set)
		for _, mandatoryHeadersItem := range mandatoryHeadersSet.List() {
			mandatoryHeaders = append(mandatoryHeaders, mandatoryHeadersItem.(string))
		}

		patterns = append(patterns, service.Pattern{
			Template:         data["template"].(string),
			SourceCIDRs:      sourceCIRDs,
			Hosts:            hosts,
			Methods:          methods,
			Paths:            paths,
			MandatoryHeaders: mandatoryHeaders,
		})
	}
	return
}

func expandHosts(m []interface{}) (hosts []service.Host) {
	for _, raw := range m {
		data := raw.(map[string]interface{})

		var originHeader []string
		originHeaderSet := data["origin_header"].(*schema.Set)
		for _, originHeaderItem := range originHeaderSet.List() {
			originHeader = append(originHeader, originHeaderItem.(string))
		}

		var target []string
		targetSet := data["target"].(*schema.Set)
		for _, targetItem := range targetSet.List() {
			target = append(target, targetItem.(string))
		}

		hosts = append(hosts, service.Host{
			OriginHeader: originHeader,
			Target:       target,
		})
	}
	return
}

func expandTokenLoc(m []interface{}) (tokenLoc service.TokenLocation) {
	if len(m) == 0 {
		return
	}
	tokenLocItem := m[0].(map[string]interface{})
	tokenLoc = service.TokenLocation{
		QueryParam:          tokenLocItem["query_param"].(string),
		AuthorizationHeader: tokenLocItem["authorization_header"].(bool),
		CustomHeader:        tokenLocItem["custom_header"].(string),
	}
	return
}

func flattenServiceAttributes(toFlatten service.Attributes) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["frontend_address"] = flattenServiceFrontendAddresses(toFlatten.FrontendAddresses)
	v["host_tag_selector"] = toFlatten.HostTagSelector
	v["tls_sni"] = toFlatten.TLSSNI
	flattened = append(flattened, v)
	return
}

func flattenServiceFrontendAddresses(toFlatten []service.FrontendAddress) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["cidr"] = item.CIDR
		v["port"] = item.Port
		flattened = append(flattened, v)
	}
	return
}

func flattenBackendAllowPatterns(toFlatten []service.BackendAllowPattern) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["hostnames"] = item.Hostnames
		v["cidrs"] = item.CIDRs
		v["ports"] = flattenServiceBackendAllowPorts(item.Ports)
		flattened = append(flattened, v)
	}
	return
}

func flattenBackendExemptedPaths(toFlatten service.ExemptedPaths) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["enabled"] = toFlatten.Enabled
	v["patterns"] = flattenServicePatterns(toFlatten.Patterns)
	flattened = append(flattened, v)
	return
}

func flattenServiceBackend(toFlatten service.Backend) (flattened []interface{}, diagnostics diag.Diagnostics) {
	v := make(map[string]interface{})
	v["target"], diagnostics = flattenServiceTarget(toFlatten.Target)
	v["backend_allow_pattern"] = flattenServiceAllowPatterns(toFlatten.AllowPatterns)
	v["connector_name"] = toFlatten.ConnectorName
	v["dns_overrides"] = toFlatten.DNSOverrides
	v["http_connect"] = toFlatten.HTTPConnect
	v["backend_allowlist"] = toFlatten.Whitelist
	flattened = append(flattened, v)
	return
}

func flattenServiceAllowPatterns(toFlatten []service.BackendAllowPattern) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["cidrs"] = item.CIDRs
		v["hostnames"] = item.Hostnames
		v["ports"] = flattenServiceBackendAllowPorts(item.Ports)
		flattened = append(flattened, v)
	}
	return
}

func flattenServiceBackendAllowPorts(toFlatten service.BackendAllowPorts) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["port_list"] = toFlatten.PortList
	v["port_range"] = flattenServicePortRanges(toFlatten.PortRanges)
	flattened = append(flattened, v)
	return
}

func flattenServicePortRanges(toFlatten []service.PortRange) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["max"] = item.Max
		v["min"] = item.Min
		flattened = append(flattened, v)
	}
	return
}

func flattenServiceTarget(toFlatten service.Target) (flattened []interface{}, diagnostics diag.Diagnostics) {
	v := make(map[string]interface{})
	port, err := strconv.Atoi(toFlatten.Port)
	if err != nil {
		diagnostics = diag.Errorf("Could not convert BackendTarget.spec.backend.target.port to int %v", toFlatten.Port)
		return
	}
	v["client_certificate"] = toFlatten.ClientCertificate
	v["name"] = toFlatten.Name
	v["tls"] = toFlatten.TLS                  // might need to convert this to string
	v["tls_insecure"] = toFlatten.TLSInsecure // might need to convert this to string
	v["port"] = port
	flattened = append(flattened, v)
	return
}

func flattenServiceCertSettings(toFlatten service.CertSettings) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["custom_tls_cert"] = flattenServiceCustomTLSCert(toFlatten.CustomTLSCert)
	v["dns_names"] = toFlatten.DNSNames
	v["letsencrypt"] = toFlatten.Letsencrypt
	flattened = append(flattened, v)
	return
}

func flattenServiceCustomTLSCert(toFlatten service.CustomTLSCert) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["cert_file"] = toFlatten.CertFile
	v["enabled"] = toFlatten.Enabled
	v["key_file"] = toFlatten.KeyFile
	flattened = append(flattened, v)
	return
}

func flattenServiceHTTPSettings(toFlatten service.HTTPSettings) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["enabled"] = toFlatten.Enabled
	v["exempted_paths"] = flattenServiceExemptedPaths(toFlatten.ExemptedPaths)
	v["http_health_check"] = flattenServiceHTTPHealthCheck(toFlatten.HTTPHealthCheck)
	v["http_redirect"] = flattenServiceHTTPRedirect(toFlatten.HTTPRedirect)
	v["headers"] = toFlatten.Headers
	v["oidc_settings"] = flattenServiceOIDCSettings(toFlatten.OIDCSettings)
	flattened = append(flattened, v)
	return
}

func flattenServiceExemptedPaths(toFlatten service.ExemptedPaths) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["enabled"] = toFlatten.Enabled
	v["paths"] = toFlatten.Paths
	v["pattern"] = flattenServicePatterns(toFlatten.Patterns)
	flattened = append(flattened, v)
	return
}

func flattenServicePatterns(toFlatten []service.Pattern) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["template"] = item.Template
		v["source_cidrs"] = item.SourceCIDRs
		v["hosts"] = flattenServiceHosts(item.Hosts)
		v["methods"] = item.Methods
		v["paths"] = item.Paths
		v["mandatory_headers"] = item.MandatoryHeaders
		flattened = append(flattened, v)
	}
	return
}

func flattenServiceHosts(toFlatten []service.Host) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["origin_header"] = item.OriginHeader
		v["target"] = item.Target
		flattened = append(flattened, v)
	}
	return
}

func flattenServiceHTTPHealthCheck(toFlatten service.HTTPHealthCheck) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["addresses"] = toFlatten.Addresses
	v["enabled"] = toFlatten.Enabled
	v["method"] = toFlatten.Method
	v["from_address"] = toFlatten.FromAddress
	v["https"] = toFlatten.HTTPS
	v["path"] = toFlatten.Path
	v["user_agent"] = toFlatten.UserAgent
	flattened = append(flattened, v)
	return
}

func flattenServiceHTTPRedirect(toFlatten service.HTTPRedirect) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["addresses"] = toFlatten.Addresses
	v["enabled"] = toFlatten.Enabled
	v["from_address"] = toFlatten.FromAddress
	v["status_code"] = toFlatten.StatusCode
	v["url"] = toFlatten.URL
	flattened = append(flattened, v)
	return
}

func flattenServiceOIDCSettings(toFlatten service.OIDCSettings) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["api_path"] = toFlatten.APIPath
	v["enabled"] = toFlatten.Enabled
	v["post_auth_redirect_path"] = toFlatten.PostAuthRedirectPath
	v["service_domain_name"] = toFlatten.ServiceDomainName
	v["suppress_device_trust_verification"] = toFlatten.SuppressDeviceTrustVerification
	v["trust_callbacks"] = toFlatten.TrustCallBacks
	flattened = append(flattened, v)
	return
}

func flattenServiceClientCIDRs(toFlatten []service.ClientCIDRs) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["address"] = flattenServiceCIDRAddresses(item.Addresses)
		v["clusters"] = item.Clusters
		v["host_tag_selector"] = item.HostTagSelector
		flattened = append(flattened, v)
	}
	return
}

func flattenServiceCIDRAddresses(toFlatten []service.CIDRAddress) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["cidr"] = item.CIDR
		v["ports"] = item.Ports
		flattened = append(flattened, v)
	}
	return
}

func flattenServiceTagSlice(toFlatten []service.ResourceTag) (flattened []interface{}) {
	for _, item := range toFlatten {
		v := make(map[string]interface{})
		v["id"] = item.ID
		v["org_id"] = item.OrgID
		v["service_id"] = item.ServiceID
		v["name"] = item.Name
		v["value"] = item.Value
		flattened = append(flattened, v)
	}
	return
}

func flattenTokenLoc(toFlatten *service.TokenLocation) (flattened interface{}) {
	if toFlatten == nil {
		return
	}
	v := make(map[string]interface{})
	v["query_param"] = toFlatten.QueryParam
	v["authorization_header"] = toFlatten.AuthorizationHeader
	v["custom_header"] = toFlatten.CustomHeader
	return
}

func validatePort() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v, err := typeSwitchPort(val)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if v < 0 || v > math.MaxUint16 {
			errs = append(errs, fmt.Errorf("%q must be in range 0-%d, got: %d ", key, math.MaxUint16, v))
		}
		return
	}
}

func typeSwitchPort(val interface{}) (v int, err error) {
	switch val.(type) {
	case int:
		v = val.(int)
	case string:
		v, err = strconv.Atoi(val.(string))
		if err != nil {
			err = fmt.Errorf("%q could not be converted to an int", val)
		}
	default:
		err = fmt.Errorf("could not validate port %q unsupported type", val)
	}
	return
}

// typeSwitchPort type switches a string pointer to an int pointer if possible
func typeSwitchPortPtr(val interface{}) (ptrv *int, err error) {
	var v int
	switch val.(type) {
	case *int:
		v = val.(int)
	case *string:
		if val.(*string) == nil {
			ptrv = nil
			return
		}
		vstring := val.(*string)
		vstringval := *vstring
		v, err = strconv.Atoi(vstringval)
		if err != nil {
			err = fmt.Errorf("%q could not be converted to an int", val)
		}
	default:
		err = fmt.Errorf("could not validate port %q unsupported type", val)
	}
	ptrv = &v
	return
}

func validateCIDR() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v == "" {
			return
		}
		_, _, err := net.ParseCIDR(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q must be a CIDR, got: %q", key, v))
		}
		return
	}
}

func validateTemplate() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v != "WEB_USER" && v != "" {
			errs = append(errs, fmt.Errorf("%q must be %q or \"\", got: %q", key, "WEB_USER", v))
		}
		return
	}
}
