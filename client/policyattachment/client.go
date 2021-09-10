package policyattachment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type policyAttachment struct {
	restClient *restclient.RestClient
}

func NewClient(restClient *restclient.RestClient) Clienter {
	policyAttachmentClient := policyAttachment{
		restClient: restClient,
	}
	return &policyAttachmentClient
}

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

func (this *policyAttachment) Create(policyID string, policyAttachment CreateBody) (createdAttachment GetBody, err error) {
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

func (this *policyAttachment) Delete(policyID string, detachBody DetachBody) (err error) {
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
