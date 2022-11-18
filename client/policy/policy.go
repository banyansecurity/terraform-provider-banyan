package policy

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"html"
	"log"
	"net/url"

	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

const apiVersion = "api/v1"
const component = "policy"

type policy struct {
	restClient *restclient.Client
}

// NewClient returns a new policy client
func NewClient(restClient *restclient.Client) Client {
	policyClient := policy{
		restClient: restClient,
	}
	return &policyClient
}

type Client interface {
	Get(id string) (spec GetPolicy, err error)
	Create(policy Object) (created GetPolicy, err error)
	Update(id string, policy Object) (updated GetPolicy, err error)
	Delete(id string) (err error)
	Detach(paClient policyattachment.Client, id string) (err error)
}

func (p *policy) Get(id string) (spec GetPolicy, err error) {
	spec, err = p.GetQuery("PolicyID", id)
	return
}

func (p *policy) Create(policy Object) (created GetPolicy, err error) {
	log.Printf("[INFO] Creating policy %s", policy.Name)
	path := "api/v1/insert_security_policy"
	body, err := json.Marshal(policy)
	if err != nil {
		return
	}
	existing, err := p.GetName(policy.Metadata.Name)
	if existing.Name == policy.Metadata.Name {
		err = fmt.Errorf("A existing policy was found with name %s (id=%s)", existing.Name, existing.ID)
		return
	}
	resp, err := p.restClient.Create(apiVersion, component, body, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &created)
	specString := html.UnescapeString(created.Spec)
	err = json.Unmarshal([]byte(specString), &created.UnmarshalledPolicy)
	return
}

func (p *policy) Update(id string, policy Object) (updated GetPolicy, err error) {
	log.Printf("[INFO] Updating policy %s", policy.Name)
	body, err := json.Marshal(policy)
	if err != nil {
		return
	}
	resp, err := p.restClient.Update(apiVersion, component, id, body, "")
	var j GetPolicy
	err = json.Unmarshal(resp, &j)
	return
}

func (p *policy) Detach(paClient policyattachment.Client, id string) (err error) {
	log.Printf("[INFO] Detaching policy %s", id)
	err = paClient.Delete(id)
	return
}

func (p *policy) Delete(id string) (err error) {
	log.Printf("[INFO] Deleting policy %s", id)
	path := "api/v1/delete_security_policy"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("PolicyID", id)
	myUrl.RawQuery = query.Encode()
	err = p.restClient.DeleteQuery(component, id, query, path)
	return
}

func (p *policy) GetQuery(key string, value string) (spec GetPolicy, err error) {
	path := "api/v1/security_policies"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set(key, value)
	resp, err := p.restClient.ReadQuery(component, query, path)
	if err != nil {
		return
	}
	var j []GetPolicy
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	if len(j) == 0 {
		err = errors.New("did not get policy")
		return
	}
	if len(j) > 1 {
		err = errors.New("got more than one policy")
		return
	}
	htmlString := html.UnescapeString(j[0].Spec)
	err = json.Unmarshal([]byte(htmlString), &j[0].UnmarshalledPolicy)
	if err != nil {
		return
	}
	spec = j[0]
	return
}

// Need to add new API query parameters
func (p *policy) GetName(name string) (spec GetPolicy, err error) {
	specs, err := p.GetAll(name)
	if err != nil {
		return
	}
	spec, err = findByName(name, specs)
	return
}

func (p *policy) GetAll(name string) (specs []GetPolicy, err error) {
	path := "api/v1/security_policies"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	resp, err := p.restClient.ReadQuery(component, query, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &specs)
	return
}

func findByName(name string, specs []GetPolicy) (spec GetPolicy, err error) {
	for _, s := range specs {
		if s.Name == name {
			return s, nil
		}
	}
	return
}
