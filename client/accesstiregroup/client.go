package accesstiregroup

import (
	"encoding/json"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

const apiVersion = "api/v2"
const component = "access_tier_groups"

type AccessTierGroup struct {
	restClient *restclient.Client
}

// NewClient returns a new client for interacting with the access tier resource
func NewClient(restClient *restclient.Client) Client {
	client := AccessTierGroup{
		restClient: restClient,
	}
	return &client
}

type Client interface {
	Create(spec AccessTierGroupPost) (created AccessTierGroupResponse, err error)
	Get(id string) (atg AccessTierGroupResponse, err error)
	Delete(id string) (err error)
	Update(id string, post AccessTierGroupPost) (updatedApiKey AccessTierGroupResponse, err error)
}

func (a *AccessTierGroup) Create(atgInfo AccessTierGroupPost) (created AccessTierGroupResponse, err error) {
	body, err := json.Marshal(atgInfo)
	if err != nil {
		return
	}
	resp, err := a.restClient.Create(apiVersion, component, body, "")
	if err != nil {
		return
	}
	var j ATGResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	created = j.Data
	return
}

func (a *AccessTierGroup) Get(id string) (atg AccessTierGroupResponse, err error) {
	resp, err := a.restClient.Read(apiVersion, component, id, "")
	if err != nil {
		return
	}
	var j ATGResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	return j.Data, nil
}

func (a *AccessTierGroup) Update(id string, post AccessTierGroupPost) (updatedApiKey AccessTierGroupResponse, err error) {
	body, err := json.Marshal(post)
	if err != nil {
		return
	}
	resp, err := a.restClient.Update(apiVersion, component, id, body, "")
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &updatedApiKey)
	return
}

func (a *AccessTierGroup) Delete(id string) (err error) {
	return a.restClient.Delete(apiVersion, component, id, "")
}
