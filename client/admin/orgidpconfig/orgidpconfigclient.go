package orgidpconfig

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/url"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"

	"github.com/pkg/errors"
)

// Clienter only supports OIDC currently
type Clienter interface {
	Get() (Spec, error)
	CreateOrUpdate(Spec) error
	// TBD if this is necessary since it's tough to delete org wide things like this. I guess we can just use creat or update to set values to essentially empty values...
	// Delete() error
}

func Client(restClient *restclient.Client) Clienter {
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

// Spec Business domain representation of the rest query
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

// Get GetOrfIdpConfig returns back the configuration for an organizations IdP
func (c *OrgIdpConfig) Get() (orgIdpConfig Spec, err error) {
	path := "api/v1/user_org_details"

	request, err := c.restClient.Get(path)
	if err != nil {
		return
	}
	// initiate request for response
	response, err := c.restClient.Do(request)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q for request: %+v with response: %+v", response.Status, request, response))
		return
	}

	defer response.Body.Close()
	responseData, err := io.ReadAll(response.Body)
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

// CreateOrUpdate CreateUpdateOrgIdpConfig creates or updates the orgs IdP
func (c *OrgIdpConfig) CreateOrUpdate(orgIdpConfig Spec) (err error) {
	path := "api/v1/update_org"

	body, err := mapToFormEncodedOrgIdpConfigBody(orgIdpConfig)
	if err != nil {
		return
	}

	request, err := c.restClient.NewRequest("POST", path, strings.NewReader(body))
	if err != nil {
		return
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.restClient.Do(request)
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
