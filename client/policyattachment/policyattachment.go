package policyattachment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type PolicyAttachment struct {
	restClient *restclient.Client
}

// NewClient returns a new policyAttachment client
func NewClient(restClient *restclient.Client) Client {
	PolicyAttachmentClient := PolicyAttachment{
		restClient: restClient,
	}
	return &PolicyAttachmentClient
}

// Client is used to perform CRUD operations against the policy attachment resource
type Client interface {
	Get(attachedToID string, attachedToType string) (attachment GetBody, err error)
	Create(policyID string, PolicyAttachment CreateBody) (createdAttachment GetBody, err error)
	Update(policyID string, PolicyAttachment CreateBody) (updatedAttachment GetBody, err error)
	Delete(policyID string, detachBody DetachBody) (err error)
	DeleteServiceAttachment(policyID string, serviceID string) (err error)
}

func (p *PolicyAttachment) Get(attachedToID string, attachedToType string) (attachment GetBody, err error) {
	path := fmt.Sprintf("api/v1/policy/attachment/%s/%s", attachedToType, attachedToID)
	response, err := p.restClient.DoGet(path)
	if err != nil {
		return
	}
	if response.StatusCode == 404 {
		err = errors.New(fmt.Sprintf("policyattachment with id %s/%s not founds", attachedToType, attachedToID))
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path))
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
	var getPolicyAttachmentJson []GetBody
	err = json.Unmarshal(responseData, &getPolicyAttachmentJson)
	if err != nil {
		return
	}
	if len(getPolicyAttachmentJson) > 1 {
		err = errors.New("got more than one policy attachment")
		return
	}
	if len(getPolicyAttachmentJson) == 0 {
		return
	}

	attachment = getPolicyAttachmentJson[0]
	isEnabled, err := strconv.ParseBool(attachment.Enabled)
	if err != nil {
		return
	}
	attachment.IsEnabled = isEnabled
	return
}

func (p *PolicyAttachment) createServiceAttachment(policyID string, PolicyAttachment CreateBody) (createdAttachment GetBody, err error) {
	path := "/api/v1/insert_security_attach_policy"
	form := url.Values{}
	form.Add("PolicyID", policyID)
	form.Add("ServiceID", PolicyAttachment.AttachedToID)
	form.Add("Enabled", PolicyAttachment.Enabled)

	request, err := p.restClient.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	response, err := p.restClient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response message: %q for request to", response.Status, string(responseData)))
		return
	}
	serviceAttachmentResponseBody := RegisteredServiceAttachCreateResponseBody{}
	err = json.Unmarshal(responseData, &serviceAttachmentResponseBody)
	if err != nil {
		return
	}
	createdAttachment.AttachedAt = serviceAttachmentResponseBody.AttachedAt
	createdAttachment.AttachedBy = serviceAttachmentResponseBody.AttachedBy
	createdAttachment.Enabled = serviceAttachmentResponseBody.Enabled
	createdAttachment.PolicyID = serviceAttachmentResponseBody.PolicyID
	createdAttachment.AttachedToID = serviceAttachmentResponseBody.ServiceID
	createdAttachment.AttachedToType = "service"
	isEnabled, err := strconv.ParseBool(createdAttachment.Enabled)
	if err != nil {
		return
	}
	createdAttachment.IsEnabled = isEnabled
	return
}

func (p *PolicyAttachment) Create(policyID string, PolicyAttachment CreateBody) (createdAttachment GetBody, err error) {
	if PolicyAttachment.AttachedToType == "service" {
		return p.createServiceAttachment(policyID, PolicyAttachment)
	}
	path := fmt.Sprintf("/api/v1/policy/%s/attach", policyID)
	body, err := json.Marshal(PolicyAttachment)
	if err != nil {
		return
	}
	response, err := p.restClient.DoPut(path, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response message: %q for request to", response.Status, string(responseData)))
		return
	}
	err = json.Unmarshal(responseData, &createdAttachment)
	if err != nil {
		return
	}

	isEnabled, err := strconv.ParseBool(createdAttachment.Enabled)
	if err != nil {
		return
	}
	createdAttachment.IsEnabled = isEnabled
	return
}

func (p *PolicyAttachment) Update(policyID string, attachment CreateBody) (updatedAttachment GetBody, err error) {
	updatedAttachment, err = p.Create(policyID, attachment)
	return
}

func (p *PolicyAttachment) DeleteServiceAttachment(policyID, serviceID string) (err error) {
	path := "api/v1/delete_security_attach_policy"

	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("PolicyID", policyID)
	query.Set("ServiceID", serviceID)
	myUrl.RawQuery = query.Encode()
	resp, err := p.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New("could not delete policy attachment")
		return
	}
	return
}

func (p *PolicyAttachment) Delete(policyID string, detachBody DetachBody) (err error) {
	if detachBody.AttachedToType == "service" {
		return p.DeleteServiceAttachment(policyID, detachBody.AttachedToID)
	}
	path := fmt.Sprintf("/api/v1/policy/%s/detach", policyID)
	body, err := json.Marshal(detachBody)
	if err != nil {
		return
	}
	response, err := p.restClient.DoPut(path, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("could not not delete policy attachment, got status code %q", response.Status))
	}
	return
}
