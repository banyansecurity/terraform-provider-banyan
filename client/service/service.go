package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
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
	Get(id string) (service GetServiceSpec, ok bool, err error)
	Create(svc CreateService) (Service GetServiceSpec, err error)
	Update(id string, svc CreateService) (Service GetServiceSpec, err error)
	Delete(id string) (err error)
}

type FrontendAddress struct {
	CIDR string `json:"cidr"`
	Port string `json:"port"`
}

type HostTag struct {
	ComBanyanopsHosttagSiteName string `json:"com.banyanops.hosttag.site_name"`
}
type Attributes struct {
	FrontendAddresses []FrontendAddress `json:"frontend_addresses"`
	HostTagSelector   []HostTag         `json:"host_tag_selector"`
	TLSSNI            []string          `json:"tls_sni"`
}

type Backend struct {
	AllowPatterns []BackendAllowPattern `json:"allow_patterns"` // unsure of what goes in here
	DNSOverrides  map[string]string     `json:"dns_overrides"`  // needs to be figured out later
	HTTPConnect   bool                  `json:"http_connect"`
	Target        Target                `json:"target"`
	Whitelist     []string              `json:"whitelist"`
}

type BackendAllowPattern struct {
	// Allowed hostnames my include a leading and/or trailing wildcard character "*"
	// to match multiple hostnames
	Hostnames []string `json:"hostnames,omitempty"`
	// Host may be a CIDR such as 10.1.1.0/24
	CIDRs []string `json:"cidrs,omitempty"`
	// List of allowed ports and port ranges
	Ports *BackendAllowPorts `json:"ports,omitempty"`
}

type BackendAllowPorts struct {
	// List of allowed ports
	PortList []int `json:"port_list,omitempty"`
	// List of allowed port ranges
	PortRanges []PortRange `json:"port_ranges,omitempty"`
}

type PortRange struct {
	// Min and Max values of the port range
	Min int `json:"min"`
	Max int `json:"max"`
}

type Target struct {
	Name              string `json:"name"`
	Port              string `json:"port"` //number
	TLS               bool   `json:"tls"`
	TLSInsecure       bool   `json:"tls_insecure"`
	ClientCertificate bool   `json:"client_certificate"`
}

type CertSettings struct {
	LetsEncrypt   bool          `json:"letsencrypt"`
	DNSNames      []string      `json:"dns_names"`
	CustomTLSCert CustomTLSCert `json:"custom_tls_cert"`
}

type CustomTLSCert struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type HTTPSettings struct {
	Enabled         bool              `json:"enabled"`
	ExemptedPaths   ExemptedPaths     `json:"exempted_paths"`
	Headers         map[string]string `json:"headers"`
	HTTPHealthCheck HTTPHealthCheck   `json:"http_health_check"`
	OIDCSettings    OIDCSettings      `json:"oidc_settings"`
}

type ExemptedPaths struct {
	Enabled  bool      `json:"enabled"`
	Paths    []string  `json:"paths"`
	Patterns []Pattern `json:"patterns"`
}

// ExemptedPaths pattern used for usecases as CORS/Source IP exception
type Pattern struct {
	SourceCIDRs      []string `json:"source_cidrs,omitempty"`
	Hosts            []Host   `json:"hosts"`
	Methods          []string `json:"methods"`
	Paths            []string `json:"paths"`
	MandatoryHeaders []string `json:"mandatory_headers"`
}

type Host struct {
	OriginHeader []string `json:"origin_header"`
	Target       []string `json:"target"`
}

type HTTPHealthCheck struct {
	Enabled     bool     `json:"enabled"`
	FromAddress []string `json:"from_address"`
	HTTPS       bool     `json:"https"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	UserAgent   string   `json:"user_agent"`
}

type OIDCSettings struct {
	APIPath              string `json:"api_path"`
	Enabled              bool   `json:"enabled"`
	PostAuthRedirectPath string `json:"post_auth_redirect_path"`
	ServiceDomainName    string `json:"service_domain_name"`
}

type Spec struct {
	Attributes   Attributes    `json:"attributes"`
	Backend      Backend       `json:"backend"`
	CertSettings CertSettings  `json:"cert_settings"`
	ClientCIDRs  []ClientCIDRs `json:"client_cidrs"`
	HTTPSettings HTTPSettings  `json:"http_settings"`
}

type CIDRAddress struct {
	CIDR  string `json:"cidr" toml:"cidr"`
	Ports string `json:"ports" toml:"ports"`
}

type ClientCIDRs struct {
	Addresses       []CIDRAddress       `json:"addresses"`
	HostTagSelector []map[string]string `json:"host_tag_selector"`
	Clusters        []string            `json:"clusters"`
}

type CreateService struct {
	Kind       string   `json:"kind"`
	APIVersion string   `json:"apiVersion"`
	Type       string   `json:"type"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

type Metadata struct {
	Name string `json:"name"`
	// FriendlyName string `json:"friendly_name"`
	Description string `json:"description"`
	Cluster     string `json:"cluster"`
	Tags        Tags   `json:"tags"`
}

type Tags struct {
	Template        string `json:"template"`
	UserFacing      string `json:"user_facing"`
	Protocol        string `json:"protocol"`
	DescriptionLink string `json:"description_link"`
	Domain          string `json:"domain"`
	Port            string `json:"port"`
	Icon            string `json:"icon"`
	ServiceAppType  string `json:"service_app_type"`
}

type GetServicesJson struct {
	ServiceID         string `json:"ServiceID"`
	ServiceName       string `json:"ServiceName"`
	ClusterName       string `json:"ClusterName"`
	ServiceType       string `json:"ServiceType"`
	ServiceDiscovery  string `json:"ServiceDiscovery"`
	ServiceVersion    int    `json:"ServiceVersion"`
	Description       string `json:"Description"`
	CreatedBy         string `json:"CreatedBy"`
	CreatedAt         int64  `json:"CreatedAt"`
	LastUpdatedBy     string `json:"LastUpdatedBy"`
	LastUpdatedAt     int64  `json:"LastUpdatedAt"`
	DeletedBy         string `json:"DeletedBy"`
	DeletedAt         int    `json:"DeletedAt"`
	External          string `json:"External"`
	OIDCEnabled       string `json:"OIDCEnabled"`
	OIDCClientSpec    string `json:"OIDCClientSpec"`
	UserFacing        string `json:"UserFacing"`
	Protocol          string `json:"Protocol"`
	Domain            string `json:"Domain"`
	Port              int    `json:"Port"`
	Enabled           string `json:"Enabled"`
	IsDefault         bool   `json:"IsDefault"`
	ServiceSpec       string `json:"ServiceSpec"`
	Spec              Spec
	CreateServiceSpec CreateService
}

type GetServiceSpec struct {
	ServiceID         string `json:"ServiceID"`
	ServiceName       string `json:"ServiceName"`
	ClusterName       string `json:"ClusterName"`
	ServiceType       string `json:"ServiceType"`
	ServiceDiscovery  string `json:"ServiceDiscovery"`
	ServiceVersion    int    `json:"ServiceVersion"`
	Description       string `json:"Description"`
	CreatedBy         string `json:"CreatedBy"`
	CreatedAt         int64  `json:"CreatedAt"`
	LastUpdatedBy     string `json:"LastUpdatedBy"`
	LastUpdatedAt     int64  `json:"LastUpdatedAt"`
	DeletedBy         string `json:"DeletedBy"`
	DeletedAt         int    `json:"DeletedAt"`
	External          string `json:"External"`
	OIDCEnabled       string `json:"OIDCEnabled"`
	OIDCClientSpec    string `json:"OIDCClientSpec"`
	UserFacing        string `json:"UserFacing"`
	Protocol          string `json:"Protocol"`
	Domain            string `json:"Domain"`
	Port              int    `json:"Port"`
	Enabled           string `json:"Enabled"`
	IsDefault         bool   `json:"IsDefault"`
	Spec              Spec
	CreateServiceSpec CreateService
}

func (this *Service) Get(id string) (service GetServiceSpec, ok bool, err error) {
	if id == "" {
		err = errors.New("need an id to get a service")
		return
	}
	path := "api/v1/registered_services"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
	response, err := this.restClient.DoGet(myUrl.String())
	if err != nil {
		return
	}
	if response.StatusCode == 404 || response.StatusCode == 400 {
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
	if len(getServicesJson) > 1 {
		err = errors.New("got more than one service")
		return
	}
	getServicesJson[0].ServiceSpec = html.UnescapeString(getServicesJson[0].ServiceSpec)
	var spec CreateService
	err = json.Unmarshal([]byte(getServicesJson[0].ServiceSpec), &spec)
	if err != nil {
		return
	}
	getServicesJson[0].CreateServiceSpec = spec
	ok = true
	service = mapToGetServiceSpec(getServicesJson[0])
	return
}

func (this *Service) Delete(id string) (err error) {
	path := "api/v1/delete_registered_service"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
	fmt.Printf("%v", myUrl.String())
	resp, err := this.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v", resp))
		return
	}
	return
}

func (this *Service) Create(svc CreateService) (service GetServiceSpec, err error) {
	path := "api/v1/insert_registered_service"
	log.Printf("@@@@ Creating a new service %#v\n", svc)
	body, err := json.Marshal(svc)
	if err != nil {
		log.Printf("@@@@ Creating a new service, found an error %#v\n", err)
		return
	}
	request, err := this.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("@@@@ Creating a new service, found an error %#v\n", err)
		return
	}
	log.Printf("@@@@ %#v", request.URL)
	response, err := this.restClient.Do(request)
	if response.StatusCode != 200 {
		log.Printf("@@@@ status code %#v, found an error %#v\n", response.StatusCode, err)
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	fmt.Printf("%s", string(responseData))
	log.Printf("@@@@ Created a new service %#v\n", string(responseData))
	var getServicesJson GetServicesJson
	err = json.Unmarshal(responseData, &getServicesJson)
	if err != nil {
		return
	}
	getServicesJson.ServiceSpec = html.UnescapeString(getServicesJson.ServiceSpec)
	var spec Spec
	err = json.Unmarshal([]byte(getServicesJson.ServiceSpec), &spec)
	if err != nil {
		return
	}
	getServicesJson.Spec = spec
	service = mapToGetServiceSpec(getServicesJson)
	return
}

func (this *Service) Update(id string, svc CreateService) (Service GetServiceSpec, err error) {
	return this.Create(svc)
}

func mapToGetServiceSpec(original GetServicesJson) (new GetServiceSpec) {
	new = GetServiceSpec{
		ClusterName:       original.ClusterName,
		ServiceID:         original.ServiceID,
		ServiceName:       original.ServiceName,
		ServiceType:       original.ServiceType,
		ServiceDiscovery:  original.ServiceDiscovery,
		ServiceVersion:    original.ServiceVersion,
		Description:       original.Description,
		CreatedBy:         original.CreatedBy,
		CreatedAt:         original.CreatedAt,
		LastUpdatedBy:     original.LastUpdatedBy,
		LastUpdatedAt:     original.LastUpdatedAt,
		DeletedBy:         original.DeletedBy,
		DeletedAt:         original.DeletedAt,
		External:          original.External,
		OIDCEnabled:       original.OIDCEnabled,
		OIDCClientSpec:    original.OIDCClientSpec,
		UserFacing:        original.UserFacing,
		Protocol:          original.Protocol,
		Domain:            original.Domain,
		Port:              original.Port,
		Enabled:           original.Enabled,
		IsDefault:         original.IsDefault,
		Spec:              original.Spec,
		CreateServiceSpec: original.CreateServiceSpec,
	}
	return
}
