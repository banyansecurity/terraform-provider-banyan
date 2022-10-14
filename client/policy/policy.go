package policy

import (
	"encoding/json"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/crud"
	"html"
	"io/ioutil"
	"net/url"

	"github.com/pkg/errors"

	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

const apiVersion = "api/v1"
const component = "policy"

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
	Get(id string) (spec GetPolicy, err error)
	Create(policy CreatePolicy) (created GetPolicy, err error)
	Update(policy CreatePolicy) (updated GetPolicy, err error)
	Detach(id string) (err error)
	Delete(id string) (err error)
}

func (p *policy) Get(id string) (spec GetPolicy, err error) {
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
	resp, err := crud.GetQuery(p.restClient, component, id, query, path)
	if err != nil {
		return
	}
	var j []GetPolicy
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	if len(j) == 0 {
		err = errors.New("did not get service")
		return
	}
	if len(j) > 1 {
		err = errors.New("got more than one service")
		return
	}
	spec = j[0]
	pol := html.UnescapeString(spec.Spec)
	err = json.Unmarshal([]byte(pol), &spec.UnmarshalledPolicy)
	if err != nil {
		return
	}
	return
}

func (p *policy) Create(policy CreatePolicy) (created GetPolicy, err error) {
	path := "api/v1/insert_security_policy"
	body, err := json.Marshal(policy)
	if err != nil {
		return
	}
	resp, err := crud.Create(p.restClient, apiVersion, component, body, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &created)
	specString := html.UnescapeString(created.Spec)
	err = json.Unmarshal([]byte(specString), &created.UnmarshalledPolicy)
	return
}

func (p *policy) Update(policy CreatePolicy) (updated GetPolicy, err error) {
	updated, err = p.Create(policy)
	return
}

func (p *policy) Detach(id string) (err error) {
	path := fmt.Sprintf("api/v1/policy/%s/attachment", id)
	myUrl, _ := url.Parse(path)
	response, err := p.restClient.DoGet(myUrl.String())
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New("could not detach policy")
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
		policyAttachmentClient := policyattachment.NewClient(p.restClient)
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

func (p *policy) Delete(id string) (err error) {
	path := "api/v1/delete_security_policy"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("PolicyID", id)
	myUrl.RawQuery = query.Encode()
	err = crud.DeleteQuery(p.restClient, component, id, query, path)
	return
}
