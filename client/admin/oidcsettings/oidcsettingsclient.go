package oidcsettings

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	restclient "github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/pkg/errors"
)

type Client interface {
	Get() (Spec, error)
}

func NewClient(restClient *restclient.Client) Client {
	c := Admin{restClient: restClient}
	return &c
}

// OidcSettings are the settings that are used for for OIDC clients
type Spec struct {
	IssuerUrl                   string `json:"issuer_url"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JwksEndpoint                string `json:"jwks_endpoint"`
	RedirectUrl                 string `json:"redirect_url"`
	Scope                       string `json:"scope"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	OpenidConfigurationEndpoint string `json:"openid_configuration_endpoint"`
}

type Admin struct {
	restClient *restclient.Client
}

func (a Admin) Get() (oidcSettings Spec, err error) {
	path := "api/v1/oidc_settings"

	request, err := a.restClient.Get(path)

	// initiate request for response
	response, err := a.restClient.Do(request)
	if err != nil {
		return
	}

	// // code here to error handle
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q for request: %+v with response: %+v", response.Status, request, response))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	err = json.Unmarshal(responseData, &oidcSettings)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	return
}
