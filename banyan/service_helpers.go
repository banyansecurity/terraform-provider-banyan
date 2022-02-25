package banyan

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
)

func expandMetatdataTags(m []interface{}) (metadatatags service.Tags) {
	if len(m) == 0 {
		return
	}
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

func expandServiceSpec(d *schema.ResourceData) (spec service.Spec) {
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

func expandAttributes(d *schema.ResourceData) (attributes service.Attributes) {
	attributes = service.Attributes{
		TLSSNI:            convertSchemaSetToStringSlice(d.Get("tls_sni").(*schema.Set)),
		FrontendAddresses: expandFrontendAddresses(d),
		HostTagSelector:   convertSliceInterfaceToSliceStringMap(d.Get("host_tag_selector").([]interface{})),
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
	backend = service.Backend{
		AllowPatterns: expandAllowPatterns(d.Get("backend.0.allow_patterns").([]interface{})),
		DNSOverrides:  convertEmptyInterfaceToStringMap(d.Get("backend.0.dns_overrides").(map[string]interface{})),
		ConnectorName: d.Get("backend.0.connector_name").(string),
		HTTPConnect:   d.Get("backend.0.http_connect").(bool),
		Target:        expandTarget(d.Get("backend.0.target").([]interface{})),
		Whitelist:     convertSchemaSetToStringSlice(d.Get("backend.0.whitelist").(*schema.Set)),
	}
	return
}

func expandAllowPatterns(m []interface{}) (allowPatterns []service.BackendAllowPattern) {
	for _, backendAllowPatternItem := range m {
		item := backendAllowPatternItem.(map[string]interface{})
		allowPatterns = append(allowPatterns, service.BackendAllowPattern{
			Hostnames: convertSchemaSetToStringSlice(item["hostnames"].(*schema.Set)),
			CIDRs:     convertSchemaSetToStringSlice(item["cidrs"].(*schema.Set)),
			Ports:     expandBackendAllowPorts(item["ports"].([]interface{})),
		})
	}
	return
}

func expandBackendAllowPorts(m []interface{}) (backendAllowPorts service.BackendAllowPorts) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	backendAllowPorts = service.BackendAllowPorts{
		PortList:   convertSchemaSetToIntSlice(itemMap["port_list"].(*schema.Set)),
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
	if len(m) == 0 {
		return
	}
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
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	certSettings = service.CertSettings{
		DNSNames:      convertSchemaSetToStringSlice(itemMap["dns_names"].(*schema.Set)),
		CustomTLSCert: expandCustomTLSCert(itemMap["custom_tls_cert"].([]interface{})),
		Letsencrypt:   itemMap["letsencrypt"].(bool),
	}
	return
}

func expandClientCIDRs(m []interface{}) (clientCIDRs []service.ClientCIDRs) {
	for _, clientCIDR := range m {
		clientCIDRItemMap := clientCIDR.(map[string]interface{})
		clientCIDRs = append(clientCIDRs, service.ClientCIDRs{
			Addresses:       expandCIDRAddress(clientCIDRItemMap["cidr_address"].([]interface{})),
			HostTagSelector: convertSliceInterfaceToSliceStringMap(clientCIDRItemMap["host_tag_selector"].([]interface{})),
			Clusters:        convertSchemaSetToStringSlice(clientCIDRItemMap["clusters"].(*schema.Set)),
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

func expandHTTPSettings(m []interface{}) (httpSettings service.HTTPSettings) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	tokenLoc := expandTokenLoc(itemMap["token_loc"].([]interface{}))
	httpSettings = service.HTTPSettings{
		Enabled:         itemMap["enabled"].(bool),
		OIDCSettings:    expandOIDCSettings(itemMap["oidc_settings"].([]interface{})),
		HTTPHealthCheck: expandHTTPHealthCheck(itemMap["http_health_check"].([]interface{})),
		// will be deprecated from api
		HTTPRedirect:  service.HTTPRedirect{},
		ExemptedPaths: expandExemptedPaths(itemMap["exempted_paths"].([]interface{})),
		Headers:       convertInterfaceMapToStringMap(itemMap["headers"].(map[string]interface{})),
		TokenLoc:      &tokenLoc,
	}
	return
}

func expandCustomTLSCert(m []interface{}) (customTLSCert service.CustomTLSCert) {
	if len(m) == 0 {
		return
	}
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
	oidcSettings = service.OIDCSettings{
		Enabled:                         itemMap["enabled"].(bool),
		ServiceDomainName:               itemMap["service_domain_name"].(string),
		PostAuthRedirectPath:            itemMap["post_auth_redirect_path"].(string),
		APIPath:                         itemMap["api_path"].(string),
		TrustCallBacks:                  convertInterfaceMapToStringMap(itemMap["trust_callbacks"].(map[string]interface{})),
		SuppressDeviceTrustVerification: itemMap["suppress_device_trust_verification"].(bool),
	}
	return
}

func expandHTTPHealthCheck(m []interface{}) (httpHealthCheck service.HTTPHealthCheck) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	httpHealthCheck = service.HTTPHealthCheck{
		Enabled:     itemMap["enabled"].(bool),
		Addresses:   convertSchemaSetToStringSlice(itemMap["addresses"].(*schema.Set)),
		Method:      itemMap["method"].(string),
		Path:        itemMap["path"].(string),
		UserAgent:   itemMap["user_agent"].(string),
		FromAddress: convertSchemaSetToStringSlice(itemMap["from_address"].(*schema.Set)),
		HTTPS:       itemMap["https"].(bool),
	}
	return
}

func expandExemptedPaths(m []interface{}) (exemptedPaths service.ExemptedPaths) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	exemptedPaths = service.ExemptedPaths{
		Enabled: itemMap["enabled"].(bool),
		// will be deprecated from API
		Paths:    make([]string, 0),
		Patterns: expandPatterns(itemMap["patterns"].([]interface{})),
	}
	return
}

func expandPatterns(m []interface{}) (patterns []service.Pattern) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		patterns = append(patterns, service.Pattern{
			Template:         data["template"].(string),
			SourceCIDRs:      convertSchemaSetToStringSlice(data["source_cidrs"].(*schema.Set)),
			Hosts:            expandHosts(data["hosts"].([]interface{})),
			Methods:          convertSchemaSetToStringSlice(data["methods"].(*schema.Set)),
			Paths:            convertSchemaSetToStringSlice(data["paths"].(*schema.Set)),
			MandatoryHeaders: convertSchemaSetToStringSlice(data["mandatory_headers"].(*schema.Set)),
		})
	}
	return
}

func expandHosts(m []interface{}) (hosts []service.Host) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		hosts = append(hosts, service.Host{
			OriginHeader: convertSchemaSetToStringSlice(data["origin_header"].(*schema.Set)),
			Target:       convertSchemaSetToStringSlice(data["target"].(*schema.Set)),
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

func flattenServiceBackend(toFlatten service.Backend) (flattened []interface{}, diagnostics diag.Diagnostics) {
	v := make(map[string]interface{})
	v["target"], diagnostics = flattenServiceTarget(toFlatten.Target)
	v["allow_patterns"] = flattenBackendAllowPatterns(toFlatten.AllowPatterns)
	v["connector_name"] = toFlatten.ConnectorName
	v["dns_overrides"] = toFlatten.DNSOverrides
	v["http_connect"] = toFlatten.HTTPConnect
	v["whitelist"] = toFlatten.Whitelist
	flattened = append(flattened, v)
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
	v["headers"] = toFlatten.Headers
	v["oidc_settings"] = flattenServiceOIDCSettings(toFlatten.OIDCSettings)
	v["token_loc"] = flattenTokenLoc(toFlatten.TokenLoc)
	flattened = append(flattened, v)
	return
}

func flattenServiceExemptedPaths(toFlatten service.ExemptedPaths) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["enabled"] = toFlatten.Enabled
	v["patterns"] = flattenServicePatterns(toFlatten.Patterns)
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
		v["cidr_address"] = flattenServiceCIDRAddresses(item.Addresses)
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

func flattenTokenLoc(toFlatten *service.TokenLocation) (flattened []interface{}) {
	if toFlatten == nil {
		return
	}
	v := make(map[string]interface{})
	v["query_param"] = toFlatten.QueryParam
	v["authorization_header"] = toFlatten.AuthorizationHeader
	v["custom_header"] = toFlatten.CustomHeader
	flattened = append(flattened, v)
	return
}
