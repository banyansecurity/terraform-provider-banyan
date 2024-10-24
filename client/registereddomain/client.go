package registereddomain

import (
	"encoding/json"
	"fmt"

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
	CreateRDChallenge(RDChallengeReqBody RegisteredDomainChallengeRequest) (RegisteredDomainChallengeID string, err error)
	GetRDChallenge(id string) (getResp RegisteredDomainChallengeInfo, err error)
	ValidateDomain(id string) (domainInfo RegisteredDomainInfo, err error)
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

func (a *RegisteredDomain) CreateRDChallenge(reqBody RegisteredDomainChallengeRequest) (RegisteredDomainChallengeID string, err error) {
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

	RegisteredDomainChallengeID = j.Data.ID

	return
}

func (a *RegisteredDomain) ValidateDomain(id string) (domainInfo RegisteredDomainInfo, err error) {

	path := fmt.Sprintf("%s/%s/%s/validate", apiVersion, registeredDomainComponent, id)

	_, err = a.restClient.Create(apiVersion, registeredDomainComponent, nil, path)
	if err != nil {
		return
	}

	return
}

func (a *RegisteredDomain) GetRDChallenge(id string) (rdChallengeInfo RegisteredDomainChallengeInfo, err error) {
	getResp, err := a.restClient.Read(apiVersion, RegisteredDomainChallengeComponent, id, "")
	if err != nil {
		return
	}

	rdChallengeInfo, err = mapChallengeInfo(getResp)
	if err != nil {
		return
	}

	return
}
