package appconfig

type AppConfigRequest struct {
	NRPTConfig *bool `json:"nrpt_config"`
}

type AppConfigRecord struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	NRPTConfig bool   `json:"nrpt_config"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

type AppConfigResponse struct {
	RequestId        string          `json:"request_id"`
	ErrorCode        int             `json:"error_code"`
	ErrorDescription string          `json:"error_description"`
	Data             AppConfigRecord `json:"data"`
}
