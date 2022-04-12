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
	Get(name string) (apikey Data, err error)
	Create(post Post) (createdApiKey Data, err error)
	Update(post Post) (updatedApiKey Data, err error)
	Delete(id string) (err error)
}

func (k *ApiKey) Get(name string) (apikey Data, err error) {
	log.Printf("[APIKEY|GET] reading apikey")
	if name == "" {
		err = errors.New("need an name to get a apikey")
		return
	}
	path := "api/experimental/v2/api_key"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := k.restClient.DoGet(myUrl.String())
	defer response.Body.Close()
	if err != nil {
		return
	}
	if response.StatusCode == 404 || response.StatusCode == 400 {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
		return
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var responseJSON Response
	err = json.Unmarshal(responseData, &responseJSON)
	if err != nil {
		return
	}
	for _, key := range responseJSON.Data {
		if key.Name == name {
			apikey = key
		}
	}
	log.Printf("[APIKEY|GET] read apikey")
	return
}

func (k *ApiKey) Create(post Post) (apikey Data, err error) {
	// check that api key does not already exist
	existingApiKey, err := k.Get(apikey.Name)
	emptyKey := Data{}
	if existingApiKey != emptyKey {
		err = errors.Errorf("API key with name %s already exists", apikey.Name)
		return
	}
	path := "api/experimental/v2/api_key"
	body, err := json.Marshal(post)
	if err != nil {
		log.Printf("[APIKEY|POST] Creating a new apikey, found an error %#v\n", err)
		return
	}
	request, err := k.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[APIKEY|POST] Creating a new request, found an error %#v\n", err)
		return
	}
	response, err := k.restClient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode == 404 || response.StatusCode == 400 {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
		return
	}
	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	apikey, err = k.Get(post.Name)
	if err != nil {
		return
	}
	log.Printf("[APIKEY|POST] created a new apikey %#v", apikey)
	return
}

func (k *ApiKey) Update(post Post) (updatedApiKey Data, err error) {
	log.Printf("[APIKEY|UPDATE] updating apikey")
	updatedApiKey, err = k.Create(Post{})
	if err != nil {
		return
	}
	log.Printf("[APIKEY|UPDATE] updated apikey")
	return
}

// Delete will disable the apikey and then delete it
func (k *ApiKey) Delete(name string) (err error) {
	apikey, err := k.Get(name)
	emptyKey := Data{}
	if apikey == emptyKey {
		return
	}
	log.Printf("[APIKEY|DELETE] deleting apikey with id %s", apikey.ID)
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
