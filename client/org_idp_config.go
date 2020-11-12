package client

import (
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// OrgIdpConfigClienter only supports OIDC currently
type OrgIdpConfigClienter interface {
	GetOrgIdpConfig() (OrgIdpConfig, error)
	CreateUpdateOrgIdpConfig(OrgIdpConfig) error
	// TBD if this is necessary since it's tough to delete org wide things...
	// DeleteOrgIdpConfig() error
}

type orgIdpConfigJson struct {
	IdpName     string `json:"IDPName"`
	IdpProtocol string `json:"IDPProto"`
	IdpConfig   string `json:"IDPConfig"`
}

// Business domain representation of the restquery
type OrgIdpConfig struct {
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
func (this *Client) GetOrgIdpConfig() (orgIdpConfig OrgIdpConfig, err error) {
	path := "api/v1/user_org_details"
	url := this.hostUrl + path

	request, err := this.newRequest("GET", url, nil)
	if err != nil {
		return
	}

	response, err := this.httpClient.Do(request)
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
	var orgIdpConfigJson OrgIdpConfigJson
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
func (this *Client) CreateUpdateOrgIdpConfig(orgIdpConfig OrgIdpConfig) (err error) {
	path := "api/v1/update_org"
	url := this.hostUrl + path

	body, err := mapToFormEncodedOrgIdpConfigBody(orgIdpConfig)

	request, err := this.newRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := this.httpClient.Do(request)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q for request: %+v with response: %+v", response.Status, request, response))
		return
	}

	return
}

func mapToFormEncodedOrgIdpConfigBody(orgIdpConfig OrgIdpConfig) (body string, err error) {

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
