package servicetunnel

import (
	"encoding/json"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"html"
	"log"
)

const apiVersion = "api/v2"
const component = "service_tunnel"

type ServiceTunnel struct {
	restClient *restclient.Client
}

// NewClient returns a new client for interacting with the access tier resource
func NewClient(restClient *restclient.Client) Client {
	client := ServiceTunnel{
		restClient: restClient,
	}
	return &client
}

type Client interface {
	Get(id string) (spec ServiceTunnelInfo, err error)
	Create(spec Info) (created ServiceTunnelInfo, err error)
	Update(id string, spec Info) (updated ServiceTunnelInfo, err error)
	Delete(id string) (err error)
	AttachPolicy(id string, post PolicyAttachmentPost) (created PolicyAttachmentInfo, err error)
	DeletePolicy(tunID string, policyID string) (err error)
	GetPolicy(id string) (policy PolicyAttachmentInfo, err error)
}

func (a *ServiceTunnel) Get(id string) (spec ServiceTunnelInfo, err error) {
	resp, err := a.restClient.Read(apiVersion, component, id, "")
	if err != nil {
		return
	}
	spec, err = specFromResponse(resp)
	return
}

func (a *ServiceTunnel) Create(spec Info) (created ServiceTunnelInfo, err error) {
	body, err := json.Marshal(Info{
		Kind:       "BanyanAccessTier",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Metadata: Metadata{
			Name:         spec.Metadata.Name,
			FriendlyName: spec.Metadata.FriendlyName,
			Description:  spec.Metadata.Description,
		},
		Spec: spec.Spec,
	})
	if err != nil {
		return
	}
	resp, err := a.restClient.Create(apiVersion, component, body, "")
	if err != nil {
		return
	}
	created, err = specFromResponse(resp)
	return
}

func (a *ServiceTunnel) Update(id string, spec Info) (updated ServiceTunnelInfo, err error) {
	body, err := json.Marshal(Info{
		Kind:       "BanyanAccessTier",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Metadata: Metadata{
			Name:         spec.Metadata.Name,
			FriendlyName: spec.Metadata.FriendlyName,
			Description:  spec.Metadata.Description,
		},
		Spec: spec.Spec,
	})
	if err != nil {
		return
	}
	resp, err := a.restClient.Update(apiVersion, component, id, body, "")
	if err != nil {
		return
	}
	updated, err = specFromResponse(resp)
	return
}

func (a *ServiceTunnel) Delete(id string) (err error) {
	err = a.restClient.Delete(apiVersion, component, id, "")
	return
}

// GetPolicy returns the policy attached to the service tunnel
func (a *ServiceTunnel) GetPolicy(id string) (policy PolicyAttachmentInfo, err error) {
	path := fmt.Sprintf("%s/%s/%s/security_policy", apiVersion, component, id)
	var j PolicyResponse
	resp, err := a.restClient.Read(apiVersion, component, id, path)
	if err != nil {
		return policy, nil
	}
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	policy = j.Data
	return
}

func (a *ServiceTunnel) AttachPolicy(id string, post PolicyAttachmentPost) (created PolicyAttachmentInfo, err error) {
	if id == "" {
		err = fmt.Errorf("need service tunnel id to attach a policy")
	}
	body, err := json.Marshal(post)
	if err != nil {
		return
	}
	// remove if there is a policy currently attached
	currentAttached, err := a.GetPolicy(id)
	if currentAttached.PolicyID != "" {
		log.Printf("[INFO] Detaching previously attached policy from service tunnel")
		a.DeletePolicy(id, currentAttached.PolicyID)
	}
	path := fmt.Sprintf("%s/%s/%s/security_policy", apiVersion, component, id)
	resp, err := a.restClient.Create(apiVersion, component, body, path)
	if err != nil {
		return
	}
	var j PolicyResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	created = j.Data
	return
}

func (a *ServiceTunnel) DeletePolicy(tunID string, policyID string) (err error) {
	path := fmt.Sprintf("%s/%s/%s/security_policy/%s", apiVersion, component, tunID, policyID)
	err = a.restClient.Delete(apiVersion, component, tunID, path)
	return
}

func specFromResponse(respData []byte) (created ServiceTunnelInfo, err error) {
	var j Response
	err = json.Unmarshal(respData, &j)
	if err != nil {
		return
	}
	spec := j.Data
	var jSpec Info
	specString := html.UnescapeString(spec.Spec)
	err = json.Unmarshal([]byte(specString), &jSpec)
	if err != nil {
		return
	}
	created = ServiceTunnelInfo{
		ID:           spec.ID,
		OrgID:        spec.OrgID,
		Name:         spec.Name,
		FriendlyName: spec.FriendlyName,
		Description:  spec.Description,
		Enabled:      spec.Enabled,
		Spec:         jSpec.Spec,
		CreatedAt:    spec.CreatedAt,
		CreatedBy:    spec.CreatedBy,
		UpdatedAt:    spec.UpdatedAt,
		UpdatedBy:    spec.UpdatedBy,
	}
	return
}
