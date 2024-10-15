package banyan

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceWeb() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of web services. For more information on web services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/hosted-websites/)",
		CreateContext: resourceServiceWebCreate,
		ReadContext:   resourceServiceWebRead,
		UpdateContext: resourceServiceWebUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        WebSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func WebSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Description: "Id of the service in Banyan",
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
		},
		"description_link": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Link shown to the end user of the banyan app for this service",
		},
		"access_tier": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the access_tier which will proxy requests to your service backend",
			ConflictsWith: []string{"connector"},
		},
		"connector": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the connector which will proxy requests to your service backend",
			ConflictsWith: []string{"access_tier"},
		},
		"domain": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The external-facing network address for this service; ex. website.example.com",
		},
		"suppress_device_trust_verification": {
			Type:        schema.TypeBool,
			Description: "suppress_device_trust_verification disables Device Trust Verification for a service if set to true",
			Optional:    true,
			Default:     false,
		},
		"port": {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "The external-facing port for this service",
			Default:      443,
			ValidateFunc: validatePort(),
		},
		"letsencrypt": {
			Type:        schema.TypeBool,
			Description: "Use a Public CA-issued server certificate instead of a Private CA-issued one",
			Optional:    true,
		},
		"backend_domain": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using http_connect",
		},
		"backend_port": {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "The internal port where this service is hosted. Default is 443",
			Default:      443,
			ValidateFunc: validatePort(),
		},
		"backend_tls": {
			Type:        schema.TypeBool,
			Description: "Indicates whether the connection to the backend server uses TLS",
			Optional:    true,
		},
		"backend_tls_insecure": {
			Type:        schema.TypeBool,
			Description: "Indicates the connection to the backend should not validate the backend server TLS certificate",
			Optional:    true,
		},
		"policy": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Policy ID to be attached to this service",
		},
		"cluster": {
			Type:        schema.TypeString,
			Description: "(Depreciated) Sets the cluster / shield for the service",
			Computed:    true,
			Optional:    true,
			Deprecated:  "This attribute is now configured automatically. This attribute will be removed in a future release of the provider.",
			ForceNew:    true,
		},
		"available_in_app": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Whether this service is available in the app for users with permission to access this service",
		},
		"icon": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Name of the icon which will be displayed to the end user. The icon names can be found in the UI in the service config",
		},
		"disable_private_dns": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "By default, Private DNS Override will be set to true i.e disable_private_dns is false. On the device, the domain name will resolve over the service tunnel to the correct Access Tier's public IP address. If you turn off Private DNS Override i.e. disable_private_dns is set to true, you need to explicitly set a private DNS entry for the service domain name.",
		},
		"custom_http_headers": {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Custom HTTP headers if set would be sent to backend, As an example this can be used to set authentication headers to authenticate user agent with backend server",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"dns_overrides": {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "dns_overrides is an optional section that specifies name-to-address or name-to-name mappings. Name-to-address mapping could be used instead of DNS lookup. Format is \"FQDN: ip_address\". Name-to-name mapping could be used to override one FQDN with the other. Format is \"FQDN1: FQDN2\" Example: name-to-address -> \"internal.myservice.com\" : \"10.23.0.1\"\n name-to-name    ->    \"exposed.service.com\" : \"internal.myservice.com\"",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"whitelist": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "whitelist is an optional section that indicates the allowed names for the backend workload instance. If this field is populated, then the backend name must match at least one entry in this field list to establish connection with the backend service.The names in this list are allowed to start with the wildcard character \"*\" to match more than one backend name. This field is used generally with http_connect=false. For all http_connect=true cases, or where more advanced backend defining patterns are required, use allow_patterns.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"custom_trust_cookie": {
			Type:     schema.TypeSet,
			MaxItems: 1,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"same_site_policy": {
						Type:         schema.TypeString,
						Optional:     true,
						ValidateFunc: validation.StringInSlice([]string{"lax", "none", "strict"}, false),
					},
					"trust_cookie_path": {
						Type:     schema.TypeString,
						Optional: true,
					},
				},
			},
		},
		"service_account_access": {
			Type:     schema.TypeSet,
			MaxItems: 1,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"authorization_header": {
						Type:     schema.TypeBool,
						Optional: true,
						Default:  false,
					},
					"query_parameter": {
						Type:     schema.TypeString,
						Optional: true,
						Default:  "",
					},
					"custom_header": {
						Type:     schema.TypeString,
						Optional: true,
						Default:  "",
					},
				},
			},
		},
		"custom_tls_cert": {
			Type:     schema.TypeSet,
			MaxItems: 1,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"key_file": {
						Type:     schema.TypeString,
						Optional: true,
						Default:  "",
					},
					"cert_file": {
						Type:     schema.TypeString,
						Optional: true,
						Default:  "",
					},
				},
			},
		},
		"exemptions": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"legacy_paths": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"paths": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"origin_header": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"source_cidrs": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"mandatory_headers": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"http_methods": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"target_domain": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
			},
		},
		"access_tier_group": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "access tier group which is associated with service",
		},
		"post_auth_redirect_path": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "redirect the user to the following path after authentication",
			Default:     "/",
		},
	}
	return
}

func resourceServiceWebCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := WebFromState(d)
	diagnostics = resourceServiceCreate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	return resourceServiceWebRead(ctx, d, m)
}

func resourceServiceWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[INFO] Reading service %s", d.Id())
	c := m.(*client.Holder)
	svc, err := c.Service.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	diagnostics = resourceServiceInfraCommonRead(svc, d, m)
	err = d.Set("backend_tls", svc.CreateServiceSpec.Spec.BackendTarget.TLS)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_tls_insecure", svc.CreateServiceSpec.Spec.BackendTarget.TLSInsecure)
	if err != nil {
		return diag.FromErr(err)
	}
	if len(svc.CreateServiceSpec.Spec.Headers) > 0 {
		err = d.Set("custom_http_headers", svc.CreateServiceSpec.Spec.Headers)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if len(svc.CreateServiceSpec.Spec.BackendDNSOverrides) > 0 {
		err = d.Set("dns_overrides", svc.CreateServiceSpec.Spec.BackendDNSOverrides)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if len(svc.CreateServiceSpec.Spec.Backend.BackendWhitelist) > 0 {
		err = d.Set("whitelist", svc.CreateServiceSpec.Spec.Backend.BackendWhitelist)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	exemptions, err := flattenExemptions(svc.CreateServiceSpec.Spec.HTTPSettings.ExemptedPaths)
	if err != nil {
		return diag.FromErr(err)
	}
	if len(exemptions) > 0 {
		err = d.Set("exemptions", exemptions)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if len(svc.CreateServiceSpec.Spec.ClientCIDRs) > 0 {
		return diag.Errorf("Client CIDRs are deprecated cannot import if it is set.")
	}
	if svc.CreateServiceSpec.Spec.CertSettings.Letsencrypt {
		err = d.Set("letsencrypt", svc.CreateServiceSpec.Spec.CertSettings.Letsencrypt)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	customTlsCert := flattenCustomTLSCert(svc.CreateServiceSpec.Spec.CustomTLSCert)
	if len(customTlsCert) != 0 {
		err = d.Set("custom_tls_cert", customTlsCert)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	err = d.Set("custom_trust_cookie", flattenCustomTrustCookie(svc.CreateServiceSpec.Spec.CustomTrustCookie))
	if err != nil {
		return diag.FromErr(err)
	}
	if svc.CreateServiceSpec.Spec.TokenLoc != nil && svc.CreateServiceSpec.Spec.TokenLoc.AuthorizationHeader {
		err = d.Set("service_account_access", flattenServiceAccountAccess(svc.CreateServiceSpec.Spec.TokenLoc))
		if err != nil {
			return diag.FromErr(err)
		}
	}

	err = d.Set("post_auth_redirect_path", svc.CreateServiceSpec.Spec.HTTPSettings.OIDCSettings.PostAuthRedirectPath)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceServiceWebUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	svc := WebFromState(d)
	diagnostics = resourceServiceUpdate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	diagnostics = resourceServiceWebRead(ctx, d, m)
	return
}

func WebFromState(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandWebMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandWebServiceSpec(d),
	}
	return
}

func expandWebMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "WEB_USER"
	userFacing := strconv.FormatBool(d.Get("available_in_app").(bool))
	protocol := "https"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "WEB"
	descriptionLink := d.Get("description_link").(string)

	metadatatags = service.Tags{
		Template:        &template,
		UserFacing:      &userFacing,
		Protocol:        &protocol,
		Domain:          &domain,
		Port:            &port,
		Icon:            &icon,
		ServiceAppType:  &serviceAppType,
		DescriptionLink: &descriptionLink,
	}
	return
}

func expandWebServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	attributes, err := expandWebAttributes(d)
	if err != nil {
		return
	}
	spec = service.Spec{
		Attributes:   attributes,
		Backend:      expandWebBackend(d),
		CertSettings: expandWebCertSettings(d),
		HTTPSettings: expandWebHTTPSettings(d),
		ClientCIDRs:  []service.ClientCIDRs{},
	}
	return
}

func expandWebAttributes(d *schema.ResourceData) (attributes service.Attributes, err error) {
	hostTagSelector, err := buildHostTagSelector(d)
	if err != nil {
		return
	}
	attributes = service.Attributes{
		TLSSNI:            []string{d.Get("domain").(string)},
		FrontendAddresses: expandWebFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
		DisablePrivateDns: d.Get("disable_private_dns").(bool),
	}
	return
}

func expandWebFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	frontendAddresses = []service.FrontendAddress{
		{
			CIDR: "",
			Port: strconv.Itoa(d.Get("port").(int)),
		},
	}
	return
}

func expandWebBackend(d *schema.ResourceData) (backend service.Backend) {
	backend = service.Backend{
		BackendTarget:       expandWebTarget(d),
		ConnectorName:       d.Get("connector").(string),
		BackendDNSOverrides: expandBackendDNSOverrides(d),
		BackendWhitelist:    expandBackendWhitelist(d),
		HttpConnect:         false,
	}
	return
}

func expandBackendWhitelist(d *schema.ResourceData) []string {
	itemsRaw := d.Get("whitelist").([]interface{})
	items := make([]string, len(itemsRaw))
	for i, raw := range itemsRaw {
		items[i] = raw.(string)
	}
	return items
}

func expandBackendDNSOverrides(d *schema.ResourceData) map[string]string {
	dnsOverrides := make(map[string]string)
	v, ok := d.GetOk("dns_overrides")

	if !ok || len(v.(map[string]interface{})) == 0 {
		return dnsOverrides
	}

	for eachKey, eachValue := range v.(map[string]interface{}) {
		dnsOverrides[eachKey] = eachValue.(string)
	}
	return dnsOverrides

}

func expandWebTarget(d *schema.ResourceData) (target service.BackendTarget) {
	return service.BackendTarget{
		Name:        d.Get("backend_domain").(string),
		Port:        strconv.Itoa(d.Get("backend_port").(int)),
		TLS:         d.Get("backend_tls").(bool),
		TLSInsecure: d.Get("backend_tls_insecure").(bool),
	}
}

func expandWebCertSettings(d *schema.ResourceData) (certSettings service.CertSettings) {
	certSettings = service.CertSettings{
		DNSNames:      []string{d.Get("domain").(string)},
		Letsencrypt:   d.Get("letsencrypt").(bool),
		CustomTLSCert: expandCustomTLSCert(d),
	}
	return
}

func expandCustomTLSCert(d *schema.ResourceData) service.CustomTLSCert {
	v, ok := d.GetOk("custom_tls_cert")
	if !ok {
		return service.CustomTLSCert{
			Enabled:  false,
			CertFile: "",
			KeyFile:  "",
		}
	}
	certFile := ""
	keyFile := ""
	ctc := v.(*schema.Set).List()
	certFile, _ = ctc[0].(map[string]interface{})["cert_file"].(string)
	keyFile, _ = ctc[0].(map[string]interface{})["key_file"].(string)

	return service.CustomTLSCert{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}
}

func expandWebHTTPSettings(d *schema.ResourceData) (httpSettings service.HTTPSettings) {
	httpSettings = service.HTTPSettings{
		Enabled:           true,
		CustomTrustCookie: expandCustomTrustCookie(d),
		OIDCSettings:      expandWebOIDCSettings(d),
		ExemptedPaths:     expandWebExemptedPaths(d),
		Headers:           expandCustomHttpHeaders(d),
		HTTPHealthCheck:   expandWebHTTPHealthCheck(),
		TokenLoc:          expandWebTokenLoc(d),
	}
	return
}
func expandCustomTrustCookie(d *schema.ResourceData) *service.CustomTrustCookie {
	v, ok := d.GetOk("custom_trust_cookie")
	if !ok {
		return nil
	}
	tc := v.(*schema.Set).List()
	sameSitePolicy := tc[0].(map[string]interface{})["same_site_policy"].(string)
	trustCookiePath := tc[0].(map[string]interface{})["trust_cookie_path"].(string)

	return &service.CustomTrustCookie{
		SameSite: sameSitePolicy,
		Path:     trustCookiePath,
	}
}
func expandWebTokenLoc(d *schema.ResourceData) *service.TokenLocation {
	v, ok := d.GetOk("service_account_access")
	if !ok {
		return nil
	}
	tc := v.(*schema.Set).List()
	authorizationHeader := tc[0].(map[string]interface{})["authorization_header"].(bool)
	customHeader := tc[0].(map[string]interface{})["custom_header"].(string)
	queryParameter := tc[0].(map[string]interface{})["query_parameter"].(string)

	return &service.TokenLocation{
		QueryParam:          queryParameter,
		AuthorizationHeader: authorizationHeader,
		CustomHeader:        customHeader,
	}
}

func expandCustomHttpHeaders(d *schema.ResourceData) map[string]string {
	customHttpHeaders := map[string]string{}
	v, ok := d.GetOk("custom_http_headers")

	if !ok || len(v.(map[string]interface{})) == 0 {
		return customHttpHeaders
	}
	for eachKey, eachValue := range v.(map[string]interface{}) {
		customHttpHeaders[eachKey] = eachValue.(string)
	}
	return customHttpHeaders
}

func expandWebOIDCSettings(d *schema.ResourceData) (oidcSettings service.OIDCSettings) {
	oidcSettings = service.OIDCSettings{
		Enabled:                         true,
		ServiceDomainName:               fmt.Sprintf("https://%s", d.Get("domain").(string)),
		APIPath:                         "",
		PostAuthRedirectPath:            d.Get("post_auth_redirect_path").(string),
		SuppressDeviceTrustVerification: d.Get("suppress_device_trust_verification").(bool),
	}
	return
}

func expandWebExemptedPaths(d *schema.ResourceData) service.ExemptedPaths {
	exemptedPaths, ok := d.GetOk("exemptions")
	if !ok {
		return service.ExemptedPaths{
			Enabled: false,
		}
	}

	paths, err := getStringListWithinSetForKey(exemptedPaths.(*schema.Set), "legacy_paths")
	if err != nil {
		diag.Errorf("Unable to read paths from exempted_paths")
	}

	patterns, err := expandExemptedPathPatterns(exemptedPaths.(*schema.Set))
	if err != nil {
		diag.Errorf("Unable to read patterns from exempted_paths")
	}

	return service.ExemptedPaths{
		Enabled:  true,
		Paths:    paths,
		Patterns: patterns,
	}
}

func expandExemptedPathPatterns(exemptedPaths *schema.Set) (patterns []service.Pattern, err error) {
	patterns = make([]service.Pattern, 0)
	for _, exemptedPath := range exemptedPaths.List() {
		exemptedPatterns, ok := exemptedPath.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("unable to parse exemptions")
			return
		}
		exemptedPatternMap := make(map[string][]string)
		for k, v := range exemptedPatterns {
			strValue := make([]string, 0)
			valueList, ok := v.([]interface{})
			if !ok {
				err = fmt.Errorf("unable to parse key %s under exemptions", k)
				return
			}
			for _, r := range valueList {
				strValue = append(strValue, r.(string))
			}
			exemptedPatternMap[k] = strValue
		}
		hosts := service.Host{
			OriginHeader: exemptedPatternMap["origin_header"],
			Target:       exemptedPatternMap["target_domain"],
		}
		pattern := service.Pattern{
			Template:         "CORS",
			SourceCIDRs:      exemptedPatternMap["source_cidrs"],
			Hosts:            []service.Host{hosts},
			Methods:          exemptedPatternMap["http_methods"],
			Paths:            exemptedPatternMap["paths"],
			MandatoryHeaders: exemptedPatternMap["mandatory_headers"],
		}
		patterns = append(patterns, pattern)
	}
	return
}
func expandWebHTTPHealthCheck() (httpHealthCheck service.HTTPHealthCheck) {
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
func flattenCustomTrustCookie(customTrustCookie *service.CustomTrustCookie) (flattened []interface{}) {
	if customTrustCookie == nil {
		return
	}
	tl := make(map[string]interface{})
	if customTrustCookie.SameSite != "" {
		tl["same_site_policy"] = customTrustCookie.SameSite
	}
	if customTrustCookie.Path != "" {
		tl["trust_cookie_path"] = customTrustCookie.Path
	}
	if len(tl) != 0 {
		flattened = append(flattened, tl)
	}
	return
}
