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
	Create(policy Object) (created GetPolicy, err error)
	Update(id string, policy Object) (updated GetPolicy, err error)
	Delete(id string) (err error)
	Detach(paClient policyattachment.Client, id string) (err error)
}

func (p *policy) Get(id string) (spec GetPolicy, err error) {
	specs, err := p.GetQuery([]KeyValue{
		{Key: "policyID", Value: id},
	})
	if err != nil {
		return spec, err
	}
	if len(specs) > 1 {
		err = errors.New(fmt.Sprintf("more than one policy found with id %s", id))
		return
	}
	return specs[0], nil
}

func (p *policy) Create(policy Object) (created GetPolicy, err error) {
	log.Printf("[INFO] Creating policy %s", policy.Name)
	existing, err := p.GetQuery([]KeyValue{
		{Key: "policyName", Value: policy.Name},
	})
	if len(existing) > 0 {
		err = errors.New(fmt.Sprintf("policy with name %s already exists", policy.Name))
		return
	}
	path := "api/v1/insert_security_policy"
	body, err := json.Marshal(policy)
	if err != nil {
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

func (p *policy) GetQuery(kvs []KeyValue) (uSpecs []GetPolicy, err error) {
	path := "api/v1/security_policies"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	for _, kv := range kvs {
		query.Add(kv.Key, kv.Value)
	}
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
	uSpecs, err = unmarshalPolicySpecs(j)
	return
}

// helper function to escape html strings in policy specs
func unmarshalPolicySpecs(specs []GetPolicy) (uSpecs []GetPolicy, err error) {
	for i, s := range specs {
		htmlString := html.UnescapeString(s.Spec)
		err = json.Unmarshal([]byte(htmlString), &s.UnmarshalledPolicy)
		if err != nil {
			err = fmt.Errorf("failed to unmarshal policy spec at position %v:\n %#v", i, s)
			return
		}
		uSpecs = append(uSpecs, s)
	}
	return
}

func (p *policy) GetNameType(name string, sType string) (spec GetPolicy, err error) {
	specs, err := p.GetQuery([]KeyValue{
		{Key: "serviceType", Value: sType},
		{Key: "policyName", Value: name},
	})
	if err != nil {
		return
	}
	if len(specs) == 0 {
		err = errors.New("did not get policy")
	}
	if len(specs) > 1 {
		err = errors.New("multiple policies found")
	}
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
