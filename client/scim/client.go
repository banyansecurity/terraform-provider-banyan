package scim

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type SCIM struct {
	restClient *restclient.Client
}

const apiVersion = "api/v2"
const scimCredentialsPath = "scim/credentials"
const scimProvisionPath = "scim/provision"
const scimTokenDeletePath = "scim/token"

func NewClient(restClient *restclient.Client) Client {
	scimClient := SCIM{
		restClient: restClient,
	}
	return &scimClient
}

type Client interface {
	Get() (scimCreds SCIMCredentialsResponse, err error)
	Create() (scimCreds createResp, err error)
	Update(post SCIMProvisionRequest, tInfo []TokenInfo) (err error)
	Delete(tInfo []TokenInfo) (err error)
	ProvisionSCIM(post SCIMProvisionRequest) (err error)
}

func (k *SCIM) Get() (scimCreds SCIMCredentialsResponse, err error) {

	path := fmt.Sprintf("%s/%s", apiVersion, scimCredentialsPath)

	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}

	response, err := k.restClient.DoGet(myUrl.String())
	if err != nil {
		err = fmt.Errorf("request to %s %s failed %w", response.Request.Method, response.Request.URL.String(), err)
		return
	}
	resp, err := restclient.HandleResponse(response)
	if err != nil {
		return
	}

	var j getResp
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	return j.Data, nil
}

func (k *SCIM) Create() (scimCreds createResp, err error) {

	//create scim credentials for org
	response, err := k.restClient.Create(apiVersion, scimCredentialsPath, nil, "")
	if err != nil {
		return
	}

	var responseData createResp
	err = json.Unmarshal(response, &responseData)
	scimCreds = responseData
	return
}

func (k *SCIM) Update(post SCIMProvisionRequest, tInfo []TokenInfo) (err error) {

	err = k.ProvisionSCIM(post)
	if err != nil {
		return
	}

	if post.IsEnabled {
		_, err = k.restClient.Create(apiVersion, scimCredentialsPath, nil, "")
		if err != nil {
			return
		}
	} else {
		err = k.Delete(tInfo)
		if err != nil {
			return
		}
	}

	return
}

func (k *SCIM) Delete(tInfo []TokenInfo) (err error) {
	for _, t := range tInfo {
		err = k.restClient.Delete(apiVersion, scimTokenDeletePath, t.UUID, "")
		if err != nil {
			return
		}
	}
	return
}

func (k *SCIM) ProvisionSCIM(post SCIMProvisionRequest) (err error) {
	body, err := json.Marshal(post)
	if err != nil {
		return
	}

	//provision scim for an org
	_, err = k.restClient.Create(apiVersion, scimProvisionPath, body, "")
	if err != nil {
		return
	}

	return
}
