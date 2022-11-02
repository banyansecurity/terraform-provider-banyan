package accesstier

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"net/url"
)

const apiVersion = "api/v2"
const component = "access_tier"

type AccessTier struct {
	restClient *restclient.RestClient
}

// NewClient returns a new client for interacting with the access tier resource
func NewClient(restClient *restclient.RestClient) Client {
	client := AccessTier{
		restClient: restClient,
	}
	return &client
}

type Client interface {
	Get(id string) (spec AccessTierInfo, err error)
	GetName(name string) (spec AccessTierInfo, err error)
	Create(spec AccessTierPost) (created AccessTierInfo, err error)
	Update(id string, spec AccessTierPost) (updated AccessTierInfo, err error)
	Delete(id string) (err error)
	GetLocalConfig(name string) (spec AccessTierLocalConfig, err error)
	UpdateLocalConfig(name string, spec AccessTierLocalConfig) (updated AccessTierLocalConfig, err error)
}

func (a *AccessTier) Get(id string) (spec AccessTierInfo, err error) {
	resp, err := a.restClient.Read(apiVersion, component, id, "")
	if err != nil {
		return
	}
	var j ATResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	return j.Data, nil
}

func (a *AccessTier) GetName(name string) (spec AccessTierInfo, err error) {
	v := url.Values{}
	v.Add("name", name)
	resp, err := a.restClient.ReadQuery(component, v, fmt.Sprintf("%s/%s", apiVersion, component))
	if err != nil {
		return
	}
	var j ATResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	if j.Count == 0 {
		err = fmt.Errorf("access tier with name %s not found", name)
		return
	}
	return j.Data, nil
}

func (a *AccessTier) Create(spec AccessTierPost) (created AccessTierInfo, err error) {
	body, err := json.Marshal(AccessTierPostBody{
		Kind:       "BanyanAccessTier",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Metadata: Metadata{
			Name: spec.Name,
		},
		Spec: spec,
	})
	resp, err := a.restClient.Create(apiVersion, component, body, "")
	if err != nil {
		return
	}
	var j ATResponse
	err = json.Unmarshal(resp, &j)
	created = j.Data
	return
}

func (a *AccessTier) Update(id string, spec AccessTierPost) (updated AccessTierInfo, err error) {
	body, err := json.Marshal(AccessTierPostBody{
		Kind:       "BanyanAccessTier",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Metadata: Metadata{
			Name: spec.Name,
		},
		Spec: spec,
	})
	resp, err := a.restClient.Update(apiVersion, component, id, body, "")
	var j ATResponse
	err = json.Unmarshal(resp, &j)
	return j.Data, nil
}

func (a *AccessTier) Delete(id string) (err error) {
	deleteNetagents(a, id)
	err = a.restClient.Delete(apiVersion, component, id, "")
	return
}

func deleteNetagents(a *AccessTier, id string) (err error) {
	spec, err := a.Get(id)
	if err != nil {
		return err
	}
	path := "api/v1/delete_netagent"
	for _, agent := range spec.Netagents {
		query := url.Values{}
		query.Add("CLUSTERNAME", spec.ClusterName)
		query.Add("HOSTNAME", agent.Hostname)
		err = a.restClient.DeleteQuery("accesstier", agent.Hostname, query, path)
		if err != nil {
			return fmt.Errorf("error deleting netagent %s from accesstier %s: %s", agent.Hostname, spec.Name, err)
		}
	}
	return
}

func (a *AccessTier) GetLocalConfig(name string) (spec AccessTierLocalConfig, err error) {
	if name == "" {
		err = errors.New("need a name to get an accesstier")
		return
	}
	path := fmt.Sprintf("api/v2/access_tier_facing/%s/config", name)
	resp, err := a.restClient.Read(apiVersion, component, name, path)
	if err != nil {
		return
	}
	var j ATLcResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	return j.Data, nil
}

func (a *AccessTier) UpdateLocalConfig(id string, spec AccessTierLocalConfig) (updated AccessTierLocalConfig, err error) {
	path := fmt.Sprintf("api/v2/access_tier/%s/config", id)
	body, err := json.Marshal(AccessTierLocalConfigSpec{
		Kind:       "BanyanAccessTierLocalConfig",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Spec:       spec,
	})
	resp, err := a.restClient.Update(apiVersion, component, id, body, path)
	var j ATLcResponse
	err = json.Unmarshal(resp, &j)
	return j.Data, nil
}
