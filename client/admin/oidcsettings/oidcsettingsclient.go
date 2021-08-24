package oidcsettings

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	restclient "github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/pkg/errors"
)

type OidcSettingsClienter interface {
	Get() (Spec, error)
}

func Client(restClient *restclient.RestClient) OidcSettingsClienter {
	newClient := OidcSettings{restClient: restClient}
	return &newClient
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

type OidcSettings struct {
	restClient *restclient.RestClient
}

func (this *OidcSettings) Get() (oidcSettings Spec, err error) {
	path := "api/v1/oidc_settings"

	request, err := this.restClient.Get(path)

	// initiate request for response
	response, err := this.restClient.Do(request)

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
