package apikey

import (
	"encoding/json"
	"github.com/banyansecurity/terraform-banyan-provider/client/crud"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type ApiKey struct {
	restClient *restclient.RestClient
}

const apiVersion = "api/v2"
const component = "api_key"

func NewClient(restClient *restclient.RestClient) Clienter {
	apikeyClient := ApiKey{
		restClient: restClient,
	}
	return &apikeyClient
}

type Clienter interface {
	Get(id string) (apikey Data, err error)
	Create(post Post) (createdApiKey Data, err error)
	Update(id string, post Post) (updatedApiKey Data, err error)
	Delete(id string) (err error)
}

func (k *ApiKey) Get(id string) (apikey Data, err error) {
	resp, err := crud.Read(k.restClient, apiVersion, component, id, "")
	if err != nil {
		return
	}
	var j Response
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	return j.Data, nil
}

func (k *ApiKey) Create(post Post) (apikey Data, err error) {
	body, err := json.Marshal(post)
	response, err := crud.Create(k.restClient, apiVersion, component, body, "")
	var responseData Response
	err = json.Unmarshal(response, &responseData)
	apikey = responseData.Data
	return
}

func (k *ApiKey) Update(id string, post Post) (updatedApiKey Data, err error) {
	body, err := json.Marshal(post)
	if err != nil {
		return
	}
	resp, err := crud.Update(k.restClient, apiVersion, component, id, body, "")
	err = json.Unmarshal(resp, &updatedApiKey)
	return
}

func (k *ApiKey) Delete(id string) (err error) {
	return crud.Delete(k.restClient, apiVersion, component, id, "")
}
