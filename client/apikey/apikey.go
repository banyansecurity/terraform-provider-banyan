package apikey

import (
	"encoding/json"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/url"
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
	resp, err := k.restClient.Read(apiVersion, component, id, "")
	if err != nil {
		return
	}
	var j CreateResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	return j.Data, nil
}

func (k *ApiKey) Create(post Post) (apikey Data, err error) {
	// check if key exists already
	responseJSON, err := getAll(k)
	apikey, err = findByName(post.Name, responseJSON)
	if err == nil {
		err = errors.Errorf("api key already exists: %s", post.Name)
		return
	}
	body, err := json.Marshal(post)
	response, err := k.restClient.Create(apiVersion, component, body, "")
	if err != nil {
		return
	}
	var responseData CreateResponse
	err = json.Unmarshal(response, &responseData)
	apikey = responseData.Data
	return
}

func (k *ApiKey) Update(id string, post Post) (updatedApiKey Data, err error) {
	body, err := json.Marshal(post)
	if err != nil {
		return
	}
	resp, err := k.restClient.Update(apiVersion, component, id, body, "")
	err = json.Unmarshal(resp, &updatedApiKey)
	return
}

func (k *ApiKey) Delete(id string) (err error) {
	return k.restClient.Delete(apiVersion, component, id, "")
}

func getAll(k *ApiKey) (responseJSON Response, err error) {
	path := "api/experimental/v2/api_key"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := k.restClient.DoGet(myUrl.String())
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		err = errors.Errorf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path)
		return
	}
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(responseData, &responseJSON)
	if err != nil {
		return
	}
	return
}

func findByName(name string, responseJSON Response) (apikey Data, err error) {
	for _, key := range responseJSON.Data {
		if key.Name == name {
			return key, nil
		}
	}
	if apikey.ID == "" {
		err = errors.Errorf("API key not found: %s", name)
	}
	return
}
