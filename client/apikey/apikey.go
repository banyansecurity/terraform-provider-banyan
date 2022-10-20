package apikey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type ApiKey struct {
	restClient *restclient.RestClient
}

// NewClient returns a new client for interacting with the apikey resource
func NewClient(restClient *restclient.RestClient) Clienter {
	apikeyClient := ApiKey{
		restClient: restClient,
	}
	return &apikeyClient
}

// Clienter is used for performing CRUD operations on the apikey resource
type Clienter interface {
	Get(id string) (apikey Data, err error)
	Create(post Post) (createdApiKey Data, err error)
	Update(post Post) (updatedApiKey Data, err error)
	Delete(id string) (err error)
}

func (k *ApiKey) Get(id string) (apikey Data, err error) {
	if id == "" {
		err = errors.New("need an id to get a apikey")
		return
	}
	responseJSON, err := getAll(k)
	if err != nil {
		return
	}
	apikey, err = findById(id, responseJSON)
	return
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

func findById(id string, responseJSON Response) (apikey Data, err error) {
	for _, key := range responseJSON.Data {
		if key.ID == id {
			return key, nil
		}
	}
	if apikey.ID == "" {
		err = errors.Errorf("API key not found: %s", id)
	}
	return
}

func (k *ApiKey) Create(post Post) (apikey Data, err error) {
	// check that api key does not already exist
	responseJSON, err := getAll(k)
	apikey, err = findByName(post.Name, responseJSON)
	if err == nil {
		err = errors.Errorf("api key already exists: %s", post.Name)
		return
	}
	path := "api/experimental/v2/api_key"
	body, err := json.Marshal(post)
	if err != nil {
		return
	}
	request, err := k.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	response, err := k.restClient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		err = errors.Errorf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path)
		return
	}
	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	responseJSON, err = getAll(k)
	if err != nil {
		return
	}
	apikey, err = findByName(post.Name, responseJSON)
	return
}

func (k *ApiKey) Update(post Post) (updatedApiKey Data, err error) {
	updatedApiKey, err = k.Create(Post{})
	if err != nil {
		return
	}
	return
}

// Delete will disable the apikey and then delete it
func (k *ApiKey) Delete(id string) (err error) {
	apikey, err := k.Get(id)
	emptyKey := Data{}
	if apikey == emptyKey {
		return
	}
	path := fmt.Sprintf("api/experimental/v2/api_key/%s", apikey.ID)
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	resp, err := k.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v", resp))
		return
	}
	log.Printf("[APIKEY|DELETE] deleted apikey with id %s", apikey.ID)
	return
}
