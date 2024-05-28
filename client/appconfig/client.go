package appconfig

import (
	"encoding/json"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

const apiVersion = "api/v2"
const component = "/org/app_config"
const path = apiVersion + component

type AppConfig struct {
	restClient *restclient.Client
}

// NewClient returns a new client for interacting with the app config resource
func NewClient(restClient *restclient.Client) Client {
	client := AppConfig{
		restClient: restClient,
	}
	return &client
}

type Client interface {
	Create(appConfig AppConfigRequest) (resp AppConfigRecord, err error)
	Get(id string) (resp AppConfigRecord, err error)
	Update(appConfig AppConfigRequest) (resp AppConfigRecord, err error)
	Delete(id string) (err error)
}

func (a *AppConfig) Create(appConfig AppConfigRequest) (created AppConfigRecord, err error) {
	body, err := json.Marshal(appConfig)
	if err != nil {
		return
	}
	resp, err := a.restClient.Create(apiVersion, component, body, path)
	if err != nil {
		return
	}

	err = json.Unmarshal(resp, &created)
	if err != nil {
		return
	}

	return
}

func (a *AppConfig) Get(id string) (get AppConfigRecord, err error) {
	resp, err := a.restClient.Read(apiVersion, component, id, path)
	if err != nil {
		return
	}

	err = json.Unmarshal(resp, &get)
	if err != nil {
		return
	}

	return
}

func (a *AppConfig) Update(appConfig AppConfigRequest) (updated AppConfigRecord, err error) {
	body, err := json.Marshal(appConfig)
	if err != nil {
		return
	}
	resp, err := a.restClient.Update(apiVersion, component, "", body, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &updated)
	return
}

func (a *AppConfig) Delete(id string) (err error) {
	return a.restClient.Delete(apiVersion, component, id, "")
}
