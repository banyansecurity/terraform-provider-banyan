package registereddomain

import (
	"encoding/json"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

const apiVersion = "api/v2"
const registeredDomainComponent = "registered_domain"
const RegisteredDomainChallengeComponent = "registered_domain_challenge"

type RegisteredDomain struct {
	restClient *restclient.Client
}

type Client interface {
	Get(id string) (resp RegisteredDomainInfo, err error)
	Create(RDReqBody RegisteredDomainRequest) (resp RegisteredDomainInfo, err error)
	Update(id string, RDReqBody RegisteredDomainRequest) (resp RegisteredDomainInfo, err error)
	Delete(id string) (err error)
	CreateRDChallenge(RDChallengeReqBody RegisteredDomainChallengeRequest) (resp RegisteredDomainChallengeInfo, err error)
}

func NewClient(restClient *restclient.Client) Client {
	client := RegisteredDomain{
		restClient: restClient,
	}
	return &client
}

func (a *RegisteredDomain) Get(id string) (resp RegisteredDomainInfo, err error) {
	getResp, err := a.restClient.Read(apiVersion, registeredDomainComponent, id, "")
	if err != nil {
		return
	}

	resp, err = mapRDInfo(getResp)
	if err != nil {
		return
	}

	return
}

func (a *RegisteredDomain) Create(reqBody RegisteredDomainRequest) (createResp RegisteredDomainInfo, err error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return
	}

	resp, err := a.restClient.Create(apiVersion, registeredDomainComponent, body, "")
	if err != nil {
		return
	}

	createResp, err = mapRDInfo(resp)
	if err != nil {
		return
	}

	return
}

func (a *RegisteredDomain) Update(id string, reqBody RegisteredDomainRequest) (updateResponse RegisteredDomainInfo, err error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return
	}
	resp, err := a.restClient.Update(apiVersion, registeredDomainComponent, id, body, "")
	if err != nil {
		return
	}
	updateResponse, err = mapRDInfo(resp)
	if err != nil {
		return
	}

	return
}

func (a *RegisteredDomain) Delete(id string) (err error) {
	err = a.restClient.Delete(apiVersion, registeredDomainComponent, id, "")
	if err != nil {
		return
	}

	return
}

func (a *RegisteredDomain) CreateRDChallenge(reqBody RegisteredDomainChallengeRequest) (createResp RegisteredDomainChallengeInfo, err error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return
	}

	resp, err := a.restClient.Create(apiVersion, RegisteredDomainChallengeComponent, body, "")
	if err != nil {
		return
	}

	var j RDChallengeResponse
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}

	createResp = j.Data

	return
}
