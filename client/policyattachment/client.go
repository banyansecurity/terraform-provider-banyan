package policyattachment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type policyAttachment struct {
	restClient *restclient.RestClient
}

// NewClient returns a new policyAttachment client
func NewClient(restClient *restclient.RestClient) Clienter {
	policyAttachmentClient := policyAttachment{
		restClient: restClient,
	}
	return &policyAttachmentClient
}

// Clienter is used to perform CRUD operations against the policy attachment resource
type Clienter interface {
	Get(policyID string, attachedToID string, attachedToType string) (attachment GetBody, ok bool, err error)
	Create(policyID string, policyAttachment CreateBody) (createdAttachment GetBody, err error)
	Update(policyID string, policyAttachment CreateBody) (updatedAttachment GetBody, err error)
	Delete(policyID string, detachBody DetachBody) (err error)
}

func (this *policyAttachment) Get(policyID string, attachedToID string, attachedToType string) (attachment GetBody, ok bool, err error) {
	log.Printf("[POLICYATTACHMENT|GET] reading policyattachment")
	path := fmt.Sprintf("api/v1/policy/attachment/%s/%s", attachedToType, attachedToID)
	response, err := this.restClient.DoGet(path)
	if err != nil {
		return
	}
	if response.StatusCode == 404 || response.StatusCode == 400 {
		defer response.Body.Close()
		responseBody, rerr := ioutil.ReadAll(response.Body)
		if rerr != nil {
			err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to get policy attachment, couldn't parse body got error %+v", response.Status, response, rerr))
			return
		}
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to get policy attachment, has message: %v", response.Status, response, string(responseBody)))
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
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
	ok = true
	log.Printf("[POLICYATTACHMENT|GET] read policyattachment")
	return
}

func (this *policyAttachment) createServiceAttachment(policyID string, policyAttachment CreateBody) (createdAttachment GetBody, err error) {
	path := "/api/v1/insert_security_attach_policy"
	log.Printf("&&&&& %#v", policyAttachment)
	form := url.Values{}
	form.Add("PolicyID", policyID)
	form.Add("ServiceID", policyAttachment.AttachedToID)
	form.Add("Enabled", policyAttachment.Enabled)

	request, err := this.restClient.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	response, err := this.restClient.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		log.Printf("[POLICYATTACHMENT|CREATE] status code %#v, with message %q\n", response.StatusCode, string(responseData))
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

func (this *policyAttachment) Create(policyID string, policyAttachment CreateBody) (createdAttachment GetBody, err error) {
	if policyAttachment.AttachedToType == "service" {
		return this.createServiceAttachment(policyID, policyAttachment)
	}
	log.Printf("[POLICYATTACHMENT|CREATE] creating policyattachment")
	path := fmt.Sprintf("/api/v1/policy/%s/attach", policyID)
	body, err := json.Marshal(policyAttachment)
	if err != nil {
		return
	}
	response, err := this.restClient.DoPut(path, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		log.Printf("[POLICYATTACHMENT|CREATE] status code %#v, with message %q\n", response.StatusCode, string(responseData))
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
	log.Printf("[POLICYATTACHMENT|CREATE] created policyattachment")
	return
}

func (this *policyAttachment) Update(policyID string, attachment CreateBody) (updatedAttachment GetBody, err error) {
	log.Printf("[POLICYATTACHMENT|UPDATE] updating policyattachment")
	updatedAttachment, err = this.Create(policyID, attachment)
	log.Printf("[POLICYATTACHMENT|UPDATE] updated policyattachment")
	return
}

func (this *policyAttachment) deleteServiceAttachment(policyID, serviceID string) (err error) {
	path := "/api/v1/delete_security_attach_policy"

	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("PolicyID", policyID)
	query.Set("ServiceID", serviceID)
	myUrl.RawQuery = query.Encode()
	resp, err := this.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	defer resp.Body.Close()
	respBody, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v with message: %s", resp, string(respBody)))
		return
	}

	return
}

func (this *policyAttachment) Delete(policyID string, detachBody DetachBody) (err error) {
	if detachBody.AttachedToType == "service" {
		return this.deleteServiceAttachment(policyID, detachBody.AttachedToID)
	}
	log.Printf("[POLICYATTACHMENT|DELETE] deleting policyattachment")
	path := fmt.Sprintf("/api/v1/policy/%s/detach", policyID)
	body, err := json.Marshal(detachBody)
	if err != nil {
		return
	}
	response, err := this.restClient.DoPut(path, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode != 200 {
		log.Printf("[POLICYATTACHMENT|DELETE] status code %#v, with message %q\n", response.StatusCode, string(responseData))
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response message: %q for request to", response.Status, string(responseData)))
		return
	}
	log.Printf("[POLICYATTACHMENT|DELETE] deleted policyattachment")
	return
}
