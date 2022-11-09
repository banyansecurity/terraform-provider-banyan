package policy

import (
	"encoding/json"
	"html"
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
	Create(policy CreatePolicy) (created GetPolicy, err error)
	Update(policy CreatePolicy) (updated GetPolicy, err error)
	Delete(id string) (err error)
	Detach(paClient policyattachment.Client, id string) (err error)
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

func (p *policy) Create(policy CreatePolicy) (created GetPolicy, err error) {
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

func (p *policy) Update(policy CreatePolicy) (updated GetPolicy, err error) {
	updated, err = p.Create(policy)
	return
}

func (p *policy) Detach(paClient policyattachment.Client, id string) (err error) {
	err = paClient.Delete(id)
	return
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
	err = p.restClient.DeleteQuery(component, id, query, path)
	return
}
