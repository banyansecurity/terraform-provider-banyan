package banyan

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"reflect"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

func validatePort() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(int)
		if v < 0 || v > math.MaxUint16 {
			errs = append(errs, fmt.Errorf("%q must be in range 0-%d, got: %d ", key, math.MaxUint16, v))
		}
		return
	}
}

func validateCIDR() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
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

func resourceService() *schema.Resource {
	log.Println("getting resource")
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceServiceCreate,
		ReadContext:   resourceServiceRead,
		UpdateContext: resourceServiceUpdate,
		DeleteContext: resourceServiceDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of your service",
			},
			"description": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "description of your service",
			},
			"cluster": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "description of your service",
			},
			"metadatatags": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "The details regarding setting up an idp. Currently only supports OIDC. SAML support is planned.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"domain": {
							Type:     schema.TypeString,
							Required: true,
						},
						"port": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validatePort(),
						},
						"protocol": {
							Type:     schema.TypeString,
							Required: true,
						},
						"service_app_type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"user_facing": {
							Type:     schema.TypeBool,
							Required: true,
						},
						"template": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validateTemplate(),
						},
					},
				},
			},
			"spec": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "The spec",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attributes": {
							Type:        schema.TypeList,
							MinItems:    1,
							MaxItems:    1,
							Required:    true,
							Description: "attributes",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"frontend_address": {
										Type:        schema.TypeList,
										MinItems:    1,
										Required:    true,
										Description: "frontend addresses",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"cidr": {
													Type:         schema.TypeString,
													Required:     true,
													ValidateFunc: validateCIDR(),
												},
												"port": {
													Type:         schema.TypeInt,
													Required:     true,
													ValidateFunc: validatePort(),
												},
											},
										},
									},
									"host_tag_selector": {
										Type:        schema.TypeList,
										MinItems:    1,
										Required:    true,
										Description: "host_tag_selector",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"site_name": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
									"tls_sni": {
										Type: schema.TypeSet,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
										Optional: true,
									},
								},
							},
						},
						"backend": {
							Type:        schema.TypeList,
							MinItems:    1,
							MaxItems:    1,
							Required:    true,
							Description: "backend",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"target": {
										Type:        schema.TypeList,
										MinItems:    1,
										Required:    true,
										Description: "target",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"client_certificate": {
													Type:     schema.TypeBool,
													Required: true,
												},
												"name": {
													Type:     schema.TypeString,
													Required: true,
												},
												"port": {
													Type:         schema.TypeInt,
													Required:     true,
													ValidateFunc: validatePort(),
												},
												"tls": {
													Type:     schema.TypeBool,
													Required: true,
												},
												"tls_insecure": {
													Type:     schema.TypeBool,
													Required: true,
												},
											},
										},
									},
								},
							},
						},
						"http_settings": {
							Type:        schema.TypeList,
							MaxItems:    1,
							MinItems:    1,
							Required:    true,
							Description: "HTTP settings used for x",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"oidc_settings": {
										Type:        schema.TypeList,
										MinItems:    1,
										MaxItems:    1,
										Required:    true,
										Description: "oidc settings",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"enabled": {
													Type:     schema.TypeBool,
													Optional: true,
												},
												"service_domain_name": {
													Type:     schema.TypeString,
													Optional: true,
												},
											},
										},
									},
								},
							},
						},
						"cert_settings": {
							Type:        schema.TypeList,
							MaxItems:    1,
							MinItems:    1,
							Required:    true,
							Description: "cert settings used for x",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"letsencrypt": {
										Type:     schema.TypeBool,
										Optional: true,
									},
									"dns_names": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceServiceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("creating resource")
	client := m.(*client.ClientHolder)
	log.Printf("#### %#v\n", d)
	name, ok := d.Get("name").(string)
	if !ok {
		err := errors.New("Couldn't type assert name")
		diagnostics = diag.FromErr(err)
		return
	}
	description, ok := d.Get("description").(string)
	if !ok {
		err := errors.New("Couldn't type assert protocol")
		diagnostics = diag.FromErr(err)
		return
	}
	cluster, ok := d.Get("cluster").(string)
	if !ok {
		err := errors.New("Couldn't type assert cluster")
		diagnostics = diag.FromErr(err)
		return
	}
	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        name,
			Description: description,
			Cluster:     cluster,
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
	}

	metadatatags, ok := d.Get("metadatatags").([]interface{})
	if !ok {
		metadatatags := reflect.TypeOf(d.Get("metadatatags"))
		err := errors.New("Couldn't type assert metadatags, type is " + fmt.Sprintf("%+v", metadatatags))
		diagnostics = diag.FromErr(err)
		return
	}
	for _, item := range metadatatags {
		ii, ok := item.(map[string]interface{})
		if !ok {
			err := errors.New("Couldn't type assert element in metadatatags")
			diagnostics = diag.FromErr(err)
			return
		}

		svc.Metadata.Tags.Domain, ok = ii["domain"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert issuerUrl"))
			return
		}
		port, ok := ii["port"].(int)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert port"))
			return
		}
		svc.Metadata.Tags.Port = strconv.Itoa(port)
		svc.Metadata.Tags.Protocol, ok = ii["protocol"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert protocol"))
			return
		}
		svc.Metadata.Tags.ServiceAppType, ok = ii["service_app_type"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert service_app_type"))
			return
		}
		userFacingMetadataTag, ok := ii["user_facing"].(bool)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert user_facing"))
			return
		}
		svc.Metadata.Tags.UserFacing = strconv.FormatBool(userFacingMetadataTag)

		svc.Metadata.Tags.Template, ok = ii["template"].(string)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert template")
			return
		}
	}

	svc.Spec.Attributes.TLSSNI = append(svc.Spec.Attributes.TLSSNI, "sni")

	spec, ok := d.Get("spec").([]interface{})
	if !ok {
		spec := reflect.TypeOf(d.Get("spec"))
		err := errors.New("Couldn't type assert spec, type is " + fmt.Sprintf("%+v", spec))
		diagnostics = diag.FromErr(err)
		return
	}
	for _, item := range spec {
		ii, ok := item.(map[string]interface{})
		if !ok {
			err := errors.New("Couldn't type assert element in metadatatags")
			diagnostics = diag.FromErr(err)
			return
		}

		attributes, ok := ii["attributes"].([]interface{})
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert attributes"))
			return
		}
		for _, attributeItem := range attributes {
			jj, ok := attributeItem.(map[string]interface{})
			if !ok {
				err := errors.New("Couldn't type assert element in attributeItems")
				diagnostics = diag.FromErr(err)
				return
			}

			tlsSNISet, ok := jj["tls_sni"].(*schema.Set)
			if !ok {
				tlsSNIMAPTYPE := reflect.TypeOf(jj["tls_sni"])
				diagnostics = diag.FromErr(errors.New("couldn't type assert tls_sni_set" + fmt.Sprintf("%+v", tlsSNIMAPTYPE)))
				return
			}
			for _, tlsSNIItem := range tlsSNISet.List() {
				tlsSNIValue, ok := tlsSNIItem.(string)
				if !ok {
					diag.FromErr(errors.New("couldn't type assert tls_sni_value"))
					return
				}
				svc.Spec.Attributes.TLSSNI = append(svc.Spec.Attributes.TLSSNI, tlsSNIValue)
			}

			frontEndAddress, ok := jj["frontend_address"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert frontend_address")
				return
			}
			for _, frontEndAddressItem := range frontEndAddress {
				frontEndAddressItemMap, ok := frontEndAddressItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert frontend_address item value %+v", reflect.TypeOf(frontEndAddressItem))
					return
				}
				cidr, ok := frontEndAddressItemMap["cidr"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert frontend_address cidr value")
					return
				}
				port, ok := frontEndAddressItemMap["port"].(int)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert frontend_address port value")
					return
				}
				svc.Spec.Attributes.FrontendAddresses = append(svc.Spec.Attributes.FrontendAddresses, service.FrontendAddress{
					CIDR: cidr,
					Port: strconv.Itoa(port),
				})

			}
			hostTagSelector, ok := jj["host_tag_selector"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert host_tag_selector")
				return
			}
			for _, hosthostTagSelectorItem := range hostTagSelector {
				hostTagSelectorMap, ok := hosthostTagSelectorItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert host tag selector item value %+v", reflect.TypeOf(hostTagSelectorMap))
					return
				}
				siteName, ok := hostTagSelectorMap["site_name"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert hosttag selecyot site name value.")

				}
				svc.Spec.Attributes.HostTagSelector = append(svc.Spec.Attributes.HostTagSelector, service.HostTag{
					ComBanyanopsHosttagSiteName: siteName,
				})
			}

		}
		backend, ok := ii["backend"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert backend")
			return
		}
		for _, backendItem := range backend {
			jj, ok := backendItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't Type assert backend item")
				return
			}
			target, ok := jj["target"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert target")
				return
			}
			for _, targetItem := range target {
				targetItemMap, ok := targetItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert target item map")
					return
				}
				clientCertificate, ok := targetItemMap["client_certificate"].(bool)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.client_certificate")
					return
				}
				svc.Spec.Backend.Target.ClientCertificate = clientCertificate

				tls, ok := targetItemMap["tls"].(bool)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.tls")
					return
				}
				svc.Spec.Backend.Target.TLS = tls

				TLSInsecure, ok := targetItemMap["tls_insecure"].(bool)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.tls_insecure")
					return
				}
				svc.Spec.Backend.Target.TLSInsecure = TLSInsecure

				svc.Spec.Backend.Target.Name, ok = targetItemMap["name"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.name")
					return
				}

				targetPortInt, ok := targetItemMap["port"].(int)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.port")
					return
				}
				svc.Spec.Backend.Target.Port = strconv.Itoa(targetPortInt)
			}
		}
		certSettings, ok := ii["cert_settings"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert certsettings")
			return
		}
		for _, certSettingsItem := range certSettings {
			certSettingsMap, ok := certSettingsItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert certsettings map")
				return
			}
			letsencrypt, ok := certSettingsMap["letsencrypt"].(bool)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert letscencrypt")
				return
			}
			svc.Spec.CertSettings.LetsEncrypt = letsencrypt

			dnsNames, ok := certSettingsMap["dns_names"].(*schema.Set)
			if !ok {
				diagnostics = diag.Errorf("couldn't type assert dns_names to type: %+v", reflect.TypeOf(certSettingsMap["dns_names"]))
				return
			}
			for _, dnsName := range dnsNames.List() {
				dnsNameValue, ok := dnsName.(string)
				if !ok {
					diagnostics = diag.FromErr(errors.New("couldn't type assert dnsNameValue"))
					return
				}
				svc.Spec.CertSettings.DNSNames = append(svc.Spec.CertSettings.DNSNames, dnsNameValue)
			}
		}
		httpSettings, ok := ii["http_settings"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert backend")
			return
		}
		for _, httpSettingsItem := range httpSettings {
			httpSettingsMap, ok := httpSettingsItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert certsettings map")
				return
			}
			enabled, ok := httpSettingsMap["enabled"].(bool)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert httpsetting enabled")
				return
			}
			svc.Spec.HTTPSettings.Enabled = enabled

			oidcSettingsList, ok := httpSettingsMap["oidc_settings"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert oidc_settings")
				return
			}
			for _, oidcSettings := range oidcSettingsList {
				oidcSetting, ok := oidcSettings.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("couldn't type assert oidcSettings value")
					return
				}
				enabled, ok := oidcSetting["enabled"].(bool)
				if !ok {
					diagnostics = diag.Errorf("couldn't type assert spec.http_settings.oidc_settings.enabled")
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.Enabled = enabled

				serviceDomainName, ok := oidcSetting["service_domain_name"].(string)
				if !ok {
					diagnostics = diag.Errorf("couldn't type assert spec.http_settings.oidc_settings.enabled")
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.ServiceDomainName = serviceDomainName
			}
		}
	}

	//fill in null values
	svc.Spec.Backend.AllowPatterns = []service.BackendAllowPattern{}
	svc.Spec.Backend.DNSOverrides = map[string]string{}
	svc.Spec.Backend.Whitelist = []string{}
	svc.Spec.ClientCIDRs = []service.ClientCIDRs{}
	svc.Spec.HTTPSettings.ExemptedPaths.Paths = []string{}
	svc.Spec.HTTPSettings.ExemptedPaths.Patterns = []service.Pattern{}
	svc.Spec.HTTPSettings.Headers = map[string]string{}
	svc.Spec.HTTPSettings.HTTPHealthCheck = service.HTTPHealthCheck{}

	log.Printf("#### toBeSetService %#v\n", svc)
	newService, err := client.Service.Create(svc)
	if err != nil {
		diag.FromErr(errors.WithMessage(err, "couldn't create new service"))
		return
	}
	log.Printf("#### newservice%#v\n", newService)
	d.SetId(newService.ServiceID)
	// make sure we don't overwrite the existing one
	return resourceServiceRead(ctx, d, m)
}

func resourceServiceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("updating resource")
	return resourceServiceCreate(ctx, d, m)
}

func resourceServiceRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("reading resource")
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "couldn't get service with id: %s", id))
		return
	}
	if !ok {
		diagnostics = diag.Errorf("couldn't find expected resource")
		return
	}
	log.Printf("#### readService: %#v", service)
	d.Set("name", service.ServiceName)
	d.Set("description", service.Description)
	d.Set("cluster", service.ClusterName)
	port, err := strconv.Atoi(service.CreateServiceSpec.Metadata.Tags.Port)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	metadataTagUserFacing, err := strconv.ParseBool(service.CreateServiceSpec.Metadata.Tags.UserFacing)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	metadatatags := map[string]interface{}{
		"domain":           service.CreateServiceSpec.Metadata.Tags.Domain,
		"port":             port,
		"protocol":         service.CreateServiceSpec.Metadata.Tags.Protocol,
		"service_app_type": service.CreateServiceSpec.Metadata.Tags.ServiceAppType,
		"user_facing":      metadataTagUserFacing,
	}
	d.Set("metadatatags", metadatatags)
	frontendPort, err := strconv.Atoi(service.CreateServiceSpec.Spec.Attributes.FrontendAddresses[0].Port)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	backendPort, err := strconv.Atoi(service.CreateServiceSpec.Spec.Attributes.FrontendAddresses[0].Port)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	spec := map[string]interface{}{
		"attributes": map[string]interface{}{
			//todo make this be able to handle n frontend addresses
			"frontend_address": map[string]interface{}{
				"cidr": service.CreateServiceSpec.Spec.Attributes.FrontendAddresses[0].CIDR,
				"port": frontendPort,
			},
			//todo make this handle n host tag selectors
			"host_tag_selector": map[string]interface{}{
				"site_name": service.CreateServiceSpec.Spec.Attributes.HostTagSelector[0],
			},
			"tls_sni": service.CreateServiceSpec.Spec.Attributes.TLSSNI,
		},
		"backend": map[string]interface{}{
			"target": map[string]interface{}{
				"client_certificate": service.CreateServiceSpec.Spec.Backend.Target.ClientCertificate,
				"name":               service.CreateServiceSpec.Spec.Backend.Target.Name,
				"port":               backendPort,
				"tls":                service.CreateServiceSpec.Spec.Backend.Target.TLS,
				"tls_insecure":       service.CreateServiceSpec.Spec.Backend.Target.TLSInsecure,
			},
		},
	}
	d.Set("spec", spec)
	d.SetId(service.ServiceID)
	return
}

func resourceServiceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.ClientHolder)
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	return
}
