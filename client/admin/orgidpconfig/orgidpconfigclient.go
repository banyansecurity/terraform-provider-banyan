package orgidpconfig

import (
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"net/url"
	"strings"

	restclient "github.com/banyansecurity/terraform-banyan-provider/client/restclient"

	"github.com/pkg/errors"
)

// OrgIdpConfigClienter only supports OIDC currently
type OrgIdpConfigClienter interface {
	Get() (Spec, error)
	CreateOrUpdate(Spec) error
	// TBD if this is necessary since it's tough to delete org wide things like this. I guess we can just use creat or update to set values to essentially empty values...
	// Delete() error
}

func Client(restClient *restclient.Client) OrgIdpConfigClienter {
	newClient := OrgIdpConfig{restClient: restClient}
	return &newClient
}

type OrgIdpConfig struct {
	restClient *restclient.Client
}

type orgIdpConfigJson struct {
	IdpName     string `json:"IDPName"`
	IdpProtocol string `json:"IDPProto"`
	IdpConfig   string `json:"IDPConfig"`
}

// Business domain representation of the rest query
type Spec struct {
	IdpName     string
	IdpProtocol string
	IdpConfig   IdpConfig
}

type IdpConfig struct {
	RedirectUrl  string `json:"RedirectURL"`
	IssuerUrl    string `json:"IssuerURL"`
	ClientId     string `json:"ClientID"`
	ClientSecret string `json:"ClientSecret"`
}

// GetOrfIdpConfig returns back the configuration for an organizations IdP
func (this *OrgIdpConfig) Get() (orgIdpConfig Spec, err error) {
	path := "api/v1/user_org_details"

	request, err := this.restClient.Get(path)

	// initiate request for response
	response, err := this.restClient.Do(request)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q for request: %+v with response: %+v", response.Status, request, response))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var orgIdpConfigJson orgIdpConfigJson
	err = json.Unmarshal(responseData, &orgIdpConfigJson)
	if err != nil {
		return
	}
	orgIdpConfigJson.IdpConfig = html.UnescapeString(orgIdpConfigJson.IdpConfig)
	var idpConfig IdpConfig
	err = json.Unmarshal([]byte(orgIdpConfigJson.IdpConfig), &idpConfig)
	if err != nil {
		return
	}
	orgIdpConfig.IdpConfig = idpConfig
	orgIdpConfig.IdpName = orgIdpConfigJson.IdpName
	orgIdpConfig.IdpProtocol = orgIdpConfigJson.IdpProtocol

	return
}

// CreateUpdateOrgIdpConfig creates or updates the org's IdP
func (this *OrgIdpConfig) CreateOrUpdate(orgIdpConfig Spec) (err error) {
	path := "api/v1/update_org"

	body, err := mapToFormEncodedOrgIdpConfigBody(orgIdpConfig)

	request, err := this.restClient.NewRequest("POST", path, strings.NewReader(body))

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := this.restClient.Do(request)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q for request: %+v with response: %+v", response.Status, request, response))
		return
	}

	return
}

func mapToFormEncodedOrgIdpConfigBody(orgIdpConfig Spec) (body string, err error) {

	idpConfigBytes, err := json.Marshal(orgIdpConfig.IdpConfig)
	if err != nil {
		return
	}
	idpConfigString := string(idpConfigBytes)
	form := url.Values{}
	form.Add("IDPName", orgIdpConfig.IdpName)
	form.Add("IDPProtocol", orgIdpConfig.IdpProtocol)
	form.Add("IDPConfig", idpConfigString)

	body = form.Encode()
	return
}
