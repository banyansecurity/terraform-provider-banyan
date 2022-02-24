package banyan

import (
	"errors"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
)

func expandMetatdataTags(m []interface{}) (metadatatags service.Tags, err error) {
	for _, config := range m {
		tags := config.(map[string]interface{})
		template := tags["template"].(string)
		userFacingMetadataTag := tags["user_facing"].(bool)
		userFacing := strconv.FormatBool(userFacingMetadataTag)
		protocol := tags["protocol"].(string)
		domain := tags["domain"].(string)
		p := tags["port"].(int)
		port := strconv.Itoa(p)
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
	}
	return
}

func expandServiceSpec(d *schema.ResourceData) (spec service.Spec, err error) {
	attributes, err := expandAttributes(d.Get("attributes"))
	if err != nil {
		err = fmt.Errorf("failed to expand service attributes")
		return
	}

	backend, err := expandBackend(d.Get("backend"))
	if err != nil {
		err = fmt.Errorf("failed to expand backend")
		return
	}

	certSettings, err := expandCertSettings(d.Get("cert"))
	if err != nil {
		return
	}

	clientCIDRs, err := expandClientCIDRs(d.Get("client_cidrs"))
	if err != nil {
		return
	}

	expandHTTPSettings, err := expandHTTPSettings(d.Get("http_settings"))
	if err != nil {
		return
	}

	tagSliceSet := d.Get("tag_slice").(*schema.Set)
	tagSlice, err := expandTagSlice(tagSliceSet.List())
	if err != nil {
		return
	}

	spec = service.Spec{
		Attributes:   attributes,
		Backend:      backend,
		CertSettings: certSettings,
		ClientCIDRs:  clientCIDRs,
		HTTPSettings: expandHTTPSettings,
		TagSlice:     tagSlice,
	}
	return
}

func expandAttributes(m interface{}) (attributes service.Attributes, err error) {
	attr, ok := m.(map[string]interface{})

	tlsSNI := make([]string, 0)
	tlsSNISet := attr["tls_sni"].(*schema.Set)
	for _, tlsSNIItem := range tlsSNISet.List() {
		tlsSNIValue, ok := tlsSNIItem.(string)
		if !ok {
			errors.New("couldn't type assert tls_sni_value")
			return
		}
		tlsSNI = append(tlsSNI, tlsSNIValue)
	}

	var frontendAddresses []service.FrontendAddress
	frontEndAddressList := attr["frontend_address"].([]interface{})
	for _, frontEndAddressItem := range frontEndAddressList {
		frontEndAddressItemMap, ok := frontEndAddressItem.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("couldn't type assert element in frontend_address, has type %T", frontEndAddressItem)
			return
		}
		cidr, ok := frontEndAddressItemMap["cidr"].(string)
		if !ok {
			// diagnostics = createTypeAssertDiagnostic("cidr", frontEndAddressItemMap["cidr"])
			return
		}
		port, ok := frontEndAddressItemMap["port"].(string)
		if !ok {
			// diagnostics = createTypeAssertDiagnostic("port", frontEndAddressItemMap["port"])
			return
		}
		frontendAddresses = append(
			frontendAddresses,
			service.FrontendAddress{
				CIDR: cidr,
				Port: port,
			},
		)
	}

	hts, ok := attr["host_tag_selector"].([]interface{})
	if !ok {
		// diagnostics = diag.Errorf("couldn't type assert host_tag_selector with type: %T", attr["host_tag_selector"])
		return
	}
	hostTagSelector, err := convertSliceInterfaceToSliceMap(hts)
	if err != nil {
		diag.Errorf("%s", err)
		return
	}
	attributes = service.Attributes{
		TLSSNI:            tlsSNI,
		FrontendAddresses: frontendAddresses,
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandBackend(m interface{}) (backend service.Backend, err error) {
	backendItemMap := m.(map[string]interface{})

	allowPatterns, err := expandAllowPatterns(backendItemMap["backend_allow_pattern"].([]interface{}))
	if err != nil {
		return
	}

	dnsOverrides, err := convertEmptyInterfaceToStringMap(backendItemMap["dns_overrides"])
	if err != nil {
		return
	}

	target, err := expandTarget(backendItemMap["target"].([]interface{}))
	if err != nil {
		return
	}
	backend = service.Backend{
		AllowPatterns: allowPatterns,
		DNSOverrides:  dnsOverrides,
		ConnectorName: backendItemMap["connector_name"].(string),
		HTTPConnect:   backendItemMap["http_connect"].(bool),
		Target:        target,
		Whitelist:     covertSchemaSetToStringSlice(backendItemMap["whitelist"].(*schema.Set)),
	}
	return
}

func expandAllowPatterns(m []interface{}) (allowPatterns []service.BackendAllowPattern, err error) {
	for _, backendAllowPatternItem := range m {
		backendAllowPatternMap := backendAllowPatternItem.(map[string]interface{})

		hostnames := covertSchemaSetToStringSlice(backendAllowPatternMap["hostnames"].(*schema.Set))

		cidrs := covertSchemaSetToStringSlice(backendAllowPatternMap["cidrs"].(*schema.Set))

		ports, err := expandBackendAllowPorts(backendAllowPatternMap["ports"].([]interface{}))
		if err != nil {
			return
		}

		allowPatterns = append(allowPatterns, service.BackendAllowPattern{
			Hostnames: hostnames,
			CIDRs:     cidrs,
			Ports:     ports,
		})
	}
	return
}

func expandBackendAllowPorts(m []interface{}) (backendAllowPorts service.BackendAllowPorts, err error) {
	for _, item := range m {
		itemMap := item.(map[string]interface{})
		portList := covertSchemaToIntSlice(itemMap["port_list"].(*schema.Set))
		portRanges := expandPortRanges(itemMap["port_range"].([]interface{}))

		backendAllowPorts = service.BackendAllowPorts{
			PortList:   portList,
			PortRanges: portRanges,
		}
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

func expandTarget(m interface{}) (target service.Target, err error) {
	targetItemMap := m.(map[string]interface{})
	target = service.Target{
		Name:              targetItemMap["name"].(string),
		Port:              targetItemMap["port"].(string),
		TLS:               targetItemMap["tls"].(bool),
		TLSInsecure:       targetItemMap["tls_insecure"].(bool),
		ClientCertificate: targetItemMap["client_certificate"].(bool),
	}
	return
}

func expandCertSettings(m interface{}) (certSettings service.CertSettings, err error) {
	certSettingsItemMap := m.(map[string]interface{})
	customTLSCert := expandCustomTLSCert(certSettingsItemMap["custom_tls_cert"])

	certSettings = service.CertSettings{
		DNSNames:      certSettingsItemMap["dns_names"].([]string),
		CustomTLSCert: customTLSCert,
		Letsencrypt:   certSettingsItemMap["letsencrypt"].(bool),
	}
	return
}

func expandClientCIDRs(m interface{}) (clientCIDRs []service.ClientCIDRs, err error) {
	mlist := m.([]interface{})
	for _, clientCIDR := range mlist {

		clientCIDRItemMap := clientCIDR.(map[string]interface{})
		clusters := covertSchemaSetToStringSlice(clientCIDRItemMap["clusters"].(*schema.Set))

		hostTagSelector, err := convertSliceInterfaceToSliceMap(clientCIDRItemMap["host_tag_selector"].([]interface{}))
		if err != nil {
			return
		}

		addresses, err := expandCIDRAddress(clientCIDRItemMap["address"].([]interface{}))
		if err != nil {
			return
		}

		clientCIDRs = append(clientCIDRs, service.ClientCIDRs{
			Addresses:       addresses,
			HostTagSelector: hostTagSelector,
			Clusters:        clusters,
		})
	}
	return
}

func expandCIDRAddress(m []interface{}) (addresses []service.CIDRAddress, err error) {
	for _, item := range m {
		itemMap := item.(map[string]interface{})
		addresses = append(addresses, service.CIDRAddress{
			CIDR:  itemMap["cidr"].(string),
			Ports: itemMap["ports"].(string),
		})
	}
	return
}

func expandHTTPSettings(m interface{}) (httpSettings service.HTTPSettings, err error) {
	itemMap := m.(map[string]interface{})

	oidcSettings, err := expandOIDCSettings(itemMap["oidc_settings"].([]interface{}))
	if err != nil {
		return
	}

	httpRedirect, err := expandHTTPRedirect(itemMap["http_redirect"].([]interface{}))
	if err != nil {
		return
	}

	exemptedPaths, err := expandExemptedPaths(itemMap["http_exempted_paths"].([]interface{}))
	if err != nil {
		return
	}

	headers, err := convertEmptyInterfaceToStringMap(itemMap["headers"])
	if err != nil {
		return
	}

	tokenLoc, err := expandTokenLoc(itemMap["token_loc"])
	if err != nil {
		return
	}

	httpSettings = service.HTTPSettings{
		Enabled:         itemMap["enabled"].(bool),
		OIDCSettings:    oidcSettings,
		HTTPHealthCheck: expandHTTPHealthCheck(itemMap["http_health_check"].([]interface{})),
		HTTPRedirect:    httpRedirect,
		ExemptedPaths:   exemptedPaths,
		Headers:         headers,
		TokenLoc:        &tokenLoc,
	}
	return
}

func expandCustomTLSCert(m interface{}) (customTLSCert service.CustomTLSCert) {
	itemMap := m.(map[string]interface{})
	customTLSCert = service.CustomTLSCert{
		Enabled:  itemMap["enabled"].(bool),
		CertFile: itemMap["cert_file"].(string),
		KeyFile:  itemMap["key_file"].(string),
	}
	return
}

func expandTagSlice(m []interface{}) (tagSlice []service.ResourceTag, err error) {
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

func expandOIDCSettings(m interface{}) (oidcSettings service.OIDCSettings, err error) {
	itemMap := m.(map[string]interface{})
	trustCallbacks, err := convertEmptyInterfaceToStringMap(itemMap["trust_callbacks"])
	if err != nil {
		return
	}
	oidcSettings = service.OIDCSettings{
		Enabled:                         itemMap["enabled"].(bool),
		ServiceDomainName:               itemMap["service_domain_name"].(string),
		PostAuthRedirectPath:            itemMap["post_auth_redirect_path"].(string),
		APIPath:                         itemMap["api_path"].(string),
		TrustCallBacks:                  trustCallbacks,
		SuppressDeviceTrustVerification: itemMap["suppress_device_trust_verification"].(bool),
	}
	return
}

func expandHTTPHealthCheck(m interface{}) (httpHealthCheck service.HTTPHealthCheck) {
	itemMap := m.(map[string]interface{})
	httpHealthCheck = service.HTTPHealthCheck{
		Enabled:     itemMap["enabled"].(bool),
		Addresses:   itemMap["addresses"].([]string),
		Method:      itemMap["method"].(string),
		Path:        itemMap["path"].(string),
		UserAgent:   itemMap["user_agent"].(string),
		FromAddress: itemMap["from_address"].([]string),
		HTTPS:       itemMap["https"].(bool),
	}
	return
}

func expandHTTPRedirect(m interface{}) (httpRedirect service.HTTPRedirect, err error) {
	itemMap := m.(map[string]interface{})
	httpRedirect = service.HTTPRedirect{
		Enabled:     itemMap["enabled"].(bool),
		Addresses:   itemMap["address"].([]string),
		FromAddress: itemMap["from_address"].([]string),
		URL:         itemMap["url"].(string),
		StatusCode:  itemMap["status_code"].(int),
	}
	return
}

func expandExemptedPaths(m interface{}) (exemptedPaths service.ExemptedPaths, err error) {
	itemMap := m.(map[string]interface{})
	patterns, err := expandPatterns(itemMap["patterns"].([]interface{}))
	exemptedPaths = service.ExemptedPaths{
		Enabled:  itemMap["enabled"].(bool),
		Paths:    itemMap["paths"].([]string),
		Patterns: patterns,
	}
	return
}

func expandPatterns(m []interface{}) (patterns []service.Pattern, err error) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		hosts, err := expandHosts(data["hosts"].([]interface{}))
		if err != nil {
			return
		}
		patterns = append(patterns, service.Pattern{
			Template:         data["template"].(string),
			SourceCIDRs:      data["source_cidrs"].([]string),
			Hosts:            hosts,
			Methods:          data["methods"].([]string),
			Paths:            data["paths"].([]string),
			MandatoryHeaders: data["mandatory_headers"].([]string),
		})
	}
	return
}

func expandHosts(m []interface{}) (hosts []service.Host, err error) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		hosts = append(hosts, service.Host{
			OriginHeader: data["origin_header"].([]string),
			Target:       data["target"].([]string),
		})
	}
	return
}

func expandTokenLoc(m interface{}) (tokenLoc service.TokenLocation, err error) {
	itemMap := m.(map[string]interface{})
	tokenLoc = service.TokenLocation{
		QueryParam:          itemMap["query_param"].(string),
		AuthorizationHeader: itemMap["authorization_header"].(bool),
		CustomHeader:        itemMap["custom_header"].(string),
	}
	return
}
