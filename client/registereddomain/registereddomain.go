package registereddomain

import "encoding/json"

type AuthUserProfile int

type RegisteredDomainRequest struct {
	RegisteredDomain
	Profile AuthUserProfile `json:"-"`
}

type RegisteredDomainInfo struct {
	ID                          string  `json:"id"`
	OrgID                       string  `json:"org_id"`
	Name                        string  `json:"name" validate:"required,validateDomainName"`
	ClusterName                 string  `json:"cluster_name" validate:"required"`
	Cname                       string  `json:"cname"`
	Description                 string  `json:"description"`
	RegisteredDomainChallengeID *string `json:"registered_domain_challenge_id,omitempty"`
	Status                      string  `json:"status"`
	CreatedAt                   int64   `json:"created_at"`
	CreatedBy                   string  `json:"created_by"`
	UpdatedAt                   int64   `json:"updated_at"`
	UpdatedBy                   string  `json:"updated_by"`
	IsDomainBanyanManaged       bool    `json:"-"`
	IsAccessTierBanyanManaged   bool    `json:"-"`
	ACMECnameDetails
}

type ACMECnameDetails struct {
	DomainName string `json:"domain_name,omitempty"`
	Cname      string `json:"acme_cname,omitempty"`
}

type RDResponse struct {
	RequestId        string               `json:"request_id"`
	ErrorCode        int                  `json:"error_code"`
	ErrorDescription string               `json:"error_description"`
	Data             RegisteredDomainInfo `json:"data"`
}

type RegisteredDomainChallengeRequest struct {
	RegisteredDomainName string `json:"registered_domain_name" validate:"required,validateDomainName"`
}

type RegisteredDomainChallengeInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Value     string `json:"value"`
	Secret    string `json:"-"`
	CreatedAt int64  `json:"created_at"`
}

func mapRDInfo(respBody []byte) (rdInfo RegisteredDomainInfo, err error) {
	var j RDResponse
	err = json.Unmarshal(respBody, &j)
	if err != nil {
		return
	}

	rdInfo = j.Data

	return
}

type RDChallengeResponse struct {
	RequestId        string                        `json:"request_id"`
	ErrorCode        int                           `json:"error_code"`
	ErrorDescription string                        `json:"error_description"`
	Data             RegisteredDomainChallengeInfo `json:"data"`
}
