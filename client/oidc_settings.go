package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
)

type OidcSettingsClienter interface {
	GetOidcSettings() (OidcSettings, error)
}

// OidcSettings are the settings that are used for for OIDC clients
type OidcSettings struct {
	IssuerUrl                   string `json:"issuer_url"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JwksEndpoint                string `json:"jwks_endpoint"`
	RedirectUrl                 string `json:"redirect_url"`
	Scope                       string `json:"scope"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	OpenidConfigurationEndpoint string `json:"openid_configuration_endpoint"`
}

// GetOidcSettings gets the oidc settings from a command center
func (this *Client) GetOidcSettings() (oidcSettings OidcSettings, err error) {
	path := "api/v1/oidc_settings"
	url := this.hostUrl + path

	client := this.httpClient

	request, err := this.newRequest("GET", url, nil)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	// initiate request for response
	response, err := client.Do(request)

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
