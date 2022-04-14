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
	log.Printf("[APIKEY|GET] reading apikey")
	apikey, ok := getOKid(id, responseJSON)
	if !ok {
		return apikey, errors.Errorf("[APIKEY|GET] could not find apikey with id %s", id)
	}
	log.Printf("[APIKEY|GET] read apikey")
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

func getOKname(name string, responseJSON Response) (apikey Data, ok bool) {
	for _, key := range responseJSON.Data {
		if key.Name == name {
			apikey = key
			ok = true
		}
	}
	return
}

func getOKid(id string, responseJSON Response) (apikey Data, ok bool) {
	for _, key := range responseJSON.Data {
		if key.ID == id {
			apikey = key
			ok = true
		}
	}
	if apikey.ID == "" {
		ok = false
	}
	return
}

func (k *ApiKey) Create(post Post) (apikey Data, err error) {
	// check that api key does not already exist
	responseJSON, err := getAll(k)
	apikey, ok := getOKname(post.Name, responseJSON)
	if ok {
		err = errors.Errorf("[APIKEY|POST] An API key with this name already exists %s", err)
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
	apikey, ok = getOKname(post.Name, responseJSON)
	if !ok {
		err = errors.Errorf("Could not get key after creation: %s", apikey.Name)
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
func (k *ApiKey) Delete(id string) (err error) {
	apikey, err := k.Get(id)
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
