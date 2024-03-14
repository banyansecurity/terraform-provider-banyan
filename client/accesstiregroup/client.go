package accesstiregroup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

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
	GetName(name string) (spec AccessTierGroupResponse, err error)
	AttachAccessTier(groupID string, ats AccessTierList) (attachedATs []string, err error)
	DetachAccessTier(groupID string, ats AccessTierList) (detachedATs []string, err error)
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

func (a *AccessTierGroup) GetName(name string) (spec AccessTierGroupResponse, err error) {
	v := url.Values{}
	v.Add("access_tier_group_name", name)
	resp, err := a.restClient.ReadQuery(component, v, fmt.Sprintf("%s/%s", apiVersion, component))
	if err != nil {
		return
	}
	type ats struct {
		AccessTierGroups []AccessTierGroupResponse `json:"access_tier_groups,omitempty"`
		Count            int                       `json:"count"`
	}
	j := struct {
		RequestId        string `json:"request_id"`
		ErrorCode        int    `json:"error_code"`
		ErrorDescription string `json:"error_description"`
		Data             ats    `json:"data"`
	}{}
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	if j.Data.Count == 0 {
		err = fmt.Errorf("access tier with name %s not found", name)
		return
	}
	for _, accessTierGroup := range j.Data.AccessTierGroups {
		if accessTierGroup.Name == name {
			spec = accessTierGroup
			break
		}
	}
	if spec.Name == "" {
		err = fmt.Errorf("access tier group with name %s not found in results %+v", name, j.Data.AccessTierGroups)
	}
	return
}

func (a *AccessTierGroup) AttachAccessTier(groupID string, ats AccessTierList) (attachedATs []string, err error) {
	body, err := json.Marshal(ats)
	if err != nil {
		return
	}
	attachURL := fmt.Sprintf("/%s/%s/attach", component, groupID)
	resp, err := a.restClient.Create(apiVersion, attachURL, body, "")
	if err != nil {
		return
	}
	var j AccessTierList
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}

	attachedATs = j.AccessTierIDs
	return
}

func (a *AccessTierGroup) DetachAccessTier(groupID string, ats AccessTierList) (detachedATs []string, err error) {
	body, err := json.Marshal(ats)
	if err != nil {
		return
	}
	detachURL := fmt.Sprintf("%s/%s/%s/detach", apiVersion, component, groupID)
	req, err := a.restClient.NewRequest(http.MethodDelete, detachURL, bytes.NewBuffer(body))
	if err != nil {
		return
	}

	HTTPClient := &http.Client{}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("error occurred while detaching access tier from group")
		return
	}

	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var j AccessTierList
	err = json.Unmarshal(response, &j)
	if err != nil {
		return
	}

	detachedATs = j.AccessTierIDs
	return
}
