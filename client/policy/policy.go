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

	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type policy struct {
	restClient *restclient.RestClient
}

// NewClient returns a new policy client
func NewClient(restClient *restclient.RestClient) PolicyClienter {
	policyClient := policy{
		restClient: restClient,
	}
	return &policyClient
}

// PolicyClienter is used for CRUD operations against the policy resource
type PolicyClienter interface {
	Get(id string) (policy GetPolicy, ok bool, err error)
	Create(policy CreatePolicy) (createdPolicy GetPolicy, err error)
	Update(policy CreatePolicy) (updatedPolicy GetPolicy, err error)
	Detach(id string) (err error)
	Delete(id string) (err error)
}

func (this *policy) Get(id string) (policy GetPolicy, ok bool, err error) {
	log.Printf("[POLICY|GET] reading policy")
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
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path))
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
	policy.Spec = html.UnescapeString(policy.Spec)

	var spec CreatePolicy
	err = json.Unmarshal([]byte(policy.Spec), &spec)
	if err != nil {
		return
	}

	policy.UnmarshalledPolicy = spec
	ok = true
	log.Printf("[POLICY|GET] read policy")
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
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		log.Printf("[POLICY|POST] status code %#v, found an error %#v\n", response.StatusCode, err)
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path))
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
	createdPolicy.Spec = html.UnescapeString(createdPolicy.Spec)
	var spec CreatePolicy
	err = json.Unmarshal([]byte(createdPolicy.Spec), &spec)
	if err != nil {
		return
	}
	createdPolicy.UnmarshalledPolicy = spec
	log.Printf("[POLICY|POST] created a new policy %#v", createdPolicy)
	return
}

func (this *policy) Update(policy CreatePolicy) (updatedPolicy GetPolicy, err error) {
	log.Printf("[POLICY|UPDATE] updating policy")
	updatedPolicy, err = this.Create(policy)
	log.Printf("[POLICY|UPDATE] updated policy")
	return
}

func (this *policy) Detach(id string) (err error) {
	path := fmt.Sprintf("api/v1/policy/%s/attachment", id)
	myUrl, _ := url.Parse(path)
	response, err := this.restClient.DoGet(myUrl.String())
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v", response))
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var policyAttachments []policyattachment.GetBody
	err = json.Unmarshal(responseData, &policyAttachments)
	if err != nil {
		return
	}
	for _, policyAtt := range policyAttachments {
		log.Printf("[POLICY|DETACH] detaching policy %s from %s", id, policyAtt.AttachedToID)
		policyAttachmentClient := policyattachment.NewClient(this.restClient)
		detachBody := policyattachment.DetachBody{
			AttachedToID:   policyAtt.AttachedToID,
			AttachedToType: policyAtt.AttachedToType,
		}
		err = policyAttachmentClient.Delete(policyAtt.PolicyID, detachBody)
		if err != nil {
			return
		}
	}
	return nil
}

func (this *policy) Delete(id string) (err error) {
	log.Printf("[POLICY|DELETE] deleting policy with id %s", id)
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
	log.Printf("[POLICY|DELETE] deleted policy with id %s", id)
	return
}
