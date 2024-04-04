package scim

type SCIMProvisionRequest struct {
	IsEnabled bool `json:"is_enabled"`
}

type SCIMCredentialsResponse struct {
	BaseURL string      `json:"base_url"`
	Tokens  []TokenInfo `json:"tokens"`
}

type CreateSCIMCredentialsResponse struct {
	BaseURL string `json:"base_url"`
	Token   string `json:"token"`
}

type TokenInfo struct {
	UUID      string `json:"uuid"`
	CreatedAt int64  `json:"created_at"`
}

type getResp struct {
	RequestID        string                  `json:"request_id"`
	ErrorCode        int                     `json:"error_code"`
	ErrorDescription string                  `json:"error_description"`
	Data             SCIMCredentialsResponse `json:"data"`
}

type createResp struct {
	RequestID        string                        `json:"request_id"`
	ErrorCode        int                           `json:"error_code"`
	ErrorDescription string                        `json:"error_description"`
	Data             CreateSCIMCredentialsResponse `json:"data"`
}
