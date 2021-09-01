package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/pkg/errors"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type policy struct {
	restClient *restclient.RestClient
}

func NewClient(restClient *restclient.RestClient) PolicyClienter {
	policyClient := policy{
		restClient: restClient,
	}
	return &policyClient
}

type PolicyClienter interface {
	Get(id string) (policy GetPolicy, ok bool, err error)
	Create(policy CreatePolicy) (createdPolicy GetPolicy, err error)
	Update(id string, policy CreatePolicy) (updatedPolicy GetPolicy, err error)
	Delete(id string) (err error)
}

func (this *policy) Get(id string) (policy GetPolicy, ok bool, err error) {
	if id == "" {
		err = errors.New("need an id to get a policy")
		return
	}
	path := "api/v1/security_policies"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("PolicyID", id)
	myUrl.RawQuery = query.Encode()
	response, err := this.restClient.DoGet(myUrl.String())
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

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var getPolicyJson []GetPolicy
	err = json.Unmarshal(responseData, &getPolicyJson)
	if err != nil {
		return
	}
	if len(getPolicyJson) == 0 {
		return
	}
	if len(getPolicyJson) > 1 {
		err = errors.New("got more than one service")
		return
	}
	policy = getPolicyJson[0]
	policy.PolicySpec = html.UnescapeString(policy.PolicySpec)

	var spec CreatePolicy
	err = json.Unmarshal([]byte(policy.PolicySpec), &spec)
	if err != nil {
		return
	}

	policy.UnmarshalledPolicy = spec
	ok = true

	return
}

func (this *policy) Create(policy CreatePolicy) (createdPolicy GetPolicy, err error) {
	path := "api/v1/insert_security_policy"
	body, err := json.Marshal(policy)
	if err != nil {
		log.Printf("[POLICY|POST] Creating a new policy, found an error %#v\n", err)
		return
	}
	request, err := this.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[POLICY|POST] Creating a new request, found an error %#v\n", err)
	}
	response, err := this.restClient.Do(request)
	if response.StatusCode != 200 {
		log.Printf("[POLICY|POST] status code %#v, found an error %#v\n", response.StatusCode, err)
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(responseData, &createdPolicy)
	if err != nil {
		return
	}
	createdPolicy.PolicySpec = html.UnescapeString(createdPolicy.PolicySpec)
	var spec CreatePolicy
	err = json.Unmarshal([]byte(createdPolicy.PolicySpec), &spec)
	if err != nil {
		return
	}
	createdPolicy.UnmarshalledPolicy = spec

	return
}

func (this *policy) Update(id string, policy CreatePolicy) (updatedPolicy GetPolicy, err error) {
	return this.Create(policy)
}

func (this *policy) Delete(id string) (err error) {
	path := "api/v1/delete_security_policy"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("PolicyID", id)
	myUrl.RawQuery = query.Encode()
	resp, err := this.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v", resp))
		return
	}
	return
}
