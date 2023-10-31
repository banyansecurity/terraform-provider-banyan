package policy

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/url"

	"github.com/pkg/errors"

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
	GetName(name string) (spec GetPolicy, err error)
	Create(policy Object) (created GetPolicy, err error)
	Update(policy Object) (updated GetPolicy, err error)
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
	// The API will always clobber, which leads to odd behavior
	// This aligns behavior with user expectations
	// Don't clobber if the policy name is in use
	existing, err := p.GetName(policy.Name)
	if err != nil {
		return
	}
	if existing.ID != "" {
		err = fmt.Errorf("the policy name %s already in use", policy.Name)
		return
	}
	resp, err := p.restClient.Create(apiVersion, component, body, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &created)
	if err != nil {
		return
	}
	specString := html.UnescapeString(created.Spec)
	err = json.Unmarshal([]byte(specString), &created.UnmarshalledPolicy)
	return
}

func (p *policy) Update(policy Object) (updated GetPolicy, err error) {
	log.Printf("[INFO] Updating policy %s", policy.Name)
	body, err := json.Marshal(policy)
	if err != nil {
		return
	}
	path := "api/v1/insert_security_policy"
	resp, err := p.restClient.Create(apiVersion, component, body, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &updated)
	if err != nil {
		return
	}
	specString := html.UnescapeString(updated.Spec)
	err = json.Unmarshal([]byte(specString), &updated.UnmarshalledPolicy)
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

// GetName Need to add new API query parameters
func (p *policy) GetName(name string) (spec GetPolicy, err error) {
	specs, err := p.GetAll()
	if err != nil {
		return
	}
	spec, err = findByName(name, specs)
	return
}

func (p *policy) GetAll() (specs []GetPolicy, err error) {
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
