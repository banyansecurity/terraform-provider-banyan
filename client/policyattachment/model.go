package policyattachment

type CreateBody struct {
	AttachedToID   string `json:"attached_to_id"`
	Enabled        string `json:"enabled"`
	IsEnabled      bool
	AttachedToType string `json:"attached_to_type"`
}

type GetBody struct {
	PolicyID       string `json:"PolicyID"`
	PolicyName     string `json:"PolicyName"`
	AttachedToID   string `json:"AttachedToID"`
	AttachedToName string `json:"AttachedToName"`
	AttachedToType string `json:"AttachedToType"`
	Enabled        string `json:"Enabled"`
	AttachedAt     int    `json:"AttachedAt"`
	AttachedBy     string `json:"AttachedBy"`
	IsEnabled      bool
}

type DetachBody struct {
	AttachedToID   string `json:"attached_to_id"`
	AttachedToType string `json:"attached_to_type"`
}
