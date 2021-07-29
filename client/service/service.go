package client

import (
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"net/url"

	restclient "github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/pkg/errors"
)

type Service struct {
	restClient *restclient.RestClient
}

func NewClient(restClient *restclient.RestClient) ServiceClienter {
	serviceClient := Service{
		restClient: restClient,
	}
	return &serviceClient
}

type ServiceClienter interface {
	Get(id string) (service GetServiceSpec, err error)
}

type GetServiceJson struct{}

type Spec struct {
	Attributes struct {
		FrontendAddresses []struct {
			Cidr string `json:"cidr"`
			Port string `json:"port"`
		} `json:"frontend_addresses"`
		HostTagSelector []struct {
			ComBanyanopsHosttagSiteName string `json:"com.banyanops.hosttag.site_name"`
		} `json:"host_tag_selector"`
		TLSSni []string `json:"tls_sni"`
	} `json:"attributes"`
	Backend struct {
		Target struct {
			Name string `json:"name"`
			Port string `json:"port"` //number
			TLS  bool   `json:"tls"`
		} `json:"target"`
		DNSOverrides struct {
		} `json:"dns_overrides"`
		// Whitelist     []interface{} `json:"whitelist"` //allowlist
		HTTPConnect bool `json:"http_connect"`
		// AllowPatterns []interface{} `json:"allow_patterns"`
	} `json:"backend"`
	CertSettings struct {
		DNSNames      []string `json:"dns_names"`
		CustomTLSCert struct {
			Enabled  bool   `json:"enabled"`
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`
		} `json:"custom_tls_cert"`
	} `json:"cert_settings"`
	HTTPSettings struct {
		Enabled      bool `json:"enabled"`
		OidcSettings struct {
			Enabled              bool   `json:"enabled"`
			ServiceDomainName    string `json:"service_domain_name"`
			PostAuthRedirectPath string `json:"post_auth_redirect_path"`
			APIPath              string `json:"api_path"`
		} `json:"oidc_settings"`
		HTTPHealthCheck struct {
			Enabled   bool   `json:"enabled"`
			Method    string `json:"method"`
			Path      string `json:"path"`
			UserAgent string `json:"user_agent"`
			// FromAddress []interface{} `json:"from_address"`
			HTTPS bool `json:"https"`
		} `json:"http_health_check"`
		ExemptedPaths struct {
			Enabled bool          `json:"enabled"`
			Paths   []interface{} `json:"paths"`
			// Patterns []struct {
			// 	Hosts []struct {
			// 		OriginHeader []interface{} `json:"origin_header"`
			// 		Target       []interface{} `json:"target"`
			// 	} `json:"hosts"`
			// 	Methods          []interface{} `json:"methods"`
			// 	MandatoryHeaders []interface{} `json:"mandatory_headers"`
			// 	Paths            []interface{} `json:"paths"`
			// 	SourceCidrs      []interface{} `json:"source_cidrs"`
			// } `json:"patterns"`
		} `json:"exempted_paths"`
	} `json:"http_settings"`
	// ClientCidrs []interface{} `json:"client_cidrs"`
}

type CreateService struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Type       string `json:"type"`
	Metadata   struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Cluster     string `json:"cluster"`
		Tags        struct {
			Template       string `json:"template"`
			UserFacing     string `json:"user_facing"`
			Protocol       string `json:"protocol"`
			Domain         string `json:"domain"`
			Port           string `json:"port"`
			Icon           string `json:"icon"`
			ServiceAppType string `json:"service_app_type"`
		} `json:"tags"`
	} `json:"metadata"`
	Spec Spec `json:"spec"`
}

type GetServicesJson struct {
	ServiceID        string `json:"ServiceID"`
	ServiceName      string `json:"ServiceName"`
	ClusterName      string `json:"ClusterName"`
	ServiceType      string `json:"ServiceType"`
	ServiceDiscovery string `json:"ServiceDiscovery"`
	ServiceVersion   int    `json:"ServiceVersion"`
	Description      string `json:"Description"`
	CreatedBy        string `json:"CreatedBy"`
	CreatedAt        int64  `json:"CreatedAt"`
	LastUpdatedBy    string `json:"LastUpdatedBy"`
	LastUpdatedAt    int64  `json:"LastUpdatedAt"`
	DeletedBy        string `json:"DeletedBy"`
	DeletedAt        int    `json:"DeletedAt"`
	External         string `json:"External"`
	OIDCEnabled      string `json:"OIDCEnabled"`
	OIDCClientSpec   string `json:"OIDCClientSpec"`
	UserFacing       string `json:"UserFacing"`
	Protocol         string `json:"Protocol"`
	Domain           string `json:"Domain"`
	Port             int    `json:"Port"`
	Enabled          string `json:"Enabled"`
	IsDefault        bool   `json:"IsDefault"`
	ServiceSpec      string `json:"ServiceSpec"`
	Spec             Spec
}

type GetServiceSpec struct {
	ServiceID        string `json:"ServiceID"`
	ServiceName      string `json:"ServiceName"`
	ClusterName      string `json:"ClusterName"`
	ServiceType      string `json:"ServiceType"`
	ServiceDiscovery string `json:"ServiceDiscovery"`
	ServiceVersion   int    `json:"ServiceVersion"`
	Description      string `json:"Description"`
	CreatedBy        string `json:"CreatedBy"`
	CreatedAt        int64  `json:"CreatedAt"`
	LastUpdatedBy    string `json:"LastUpdatedBy"`
	LastUpdatedAt    int64  `json:"LastUpdatedAt"`
	DeletedBy        string `json:"DeletedBy"`
	DeletedAt        int    `json:"DeletedAt"`
	External         string `json:"External"`
	OIDCEnabled      string `json:"OIDCEnabled"`
	OIDCClientSpec   string `json:"OIDCClientSpec"`
	UserFacing       string `json:"UserFacing"`
	Protocol         string `json:"Protocol"`
	Domain           string `json:"Domain"`
	Port             int    `json:"Port"`
	Enabled          string `json:"Enabled"`
	IsDefault        bool   `json:"IsDefault"`
	Spec             Spec
}

func (this *Service) Get(id string) (service GetServiceSpec, err error) {
	path := "api/v1/registered_services"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	myUrl.Query().Add("ServiceID", id)
	_ = myUrl.ForceQuery
	response, err := this.restClient.DoGet(path)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var getServicesJson []GetServicesJson
	err = json.Unmarshal(responseData, &getServicesJson)
	if err != nil {
		return
	}
	if len(getServicesJson) == 0 {
		return
	}
	getServicesJson[0].ServiceSpec = html.UnescapeString(getServicesJson[0].ServiceSpec)
	var spec Spec
	err = json.Unmarshal([]byte(getServicesJson[0].ServiceSpec), &spec)
	if err != nil {
		return
	}
	getServicesJson[0].Spec = spec
	service = mapToGetServiceSpec(getServicesJson[0])
	return service, nil
}

func mapToGetServiceSpec(original GetServicesJson) (new GetServiceSpec) {
	new = GetServiceSpec{
		ClusterName:      original.ClusterName,
		ServiceID:        original.ServiceID,
		ServiceName:      original.ServiceName,
		ServiceType:      original.ServiceType,
		ServiceDiscovery: original.ServiceDiscovery,
		ServiceVersion:   original.ServiceVersion,
		Description:      original.Description,
		CreatedBy:        original.CreatedBy,
		CreatedAt:        original.CreatedAt,
		LastUpdatedBy:    original.LastUpdatedBy,
		LastUpdatedAt:    original.LastUpdatedAt,
		DeletedBy:        original.DeletedBy,
		DeletedAt:        original.DeletedAt,
		External:         original.External,
		OIDCEnabled:      original.OIDCEnabled,
		OIDCClientSpec:   original.OIDCClientSpec,
		UserFacing:       original.UserFacing,
		Protocol:         original.Protocol,
		Domain:           original.Domain,
		Port:             original.Port,
		Enabled:          original.Enabled,
		IsDefault:        original.IsDefault,
		Spec:             original.Spec,
	}
	return
}
