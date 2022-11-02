package accesstier

//EnduserDeviceTunnelConfigInfo used to send enduser device tunnel config data from restapi to shield over web socket
type EnduserDeviceTunnelConfigInfo struct {
	ID                 string   `json:"id"`
	OrgID              string   `json:"org_id"`
	Email              string   `json:"email"`
	SerialNumber       string   `json:"serial_number"`
	Roles              []string `json:"roles"`
	TunnelIPAddress    string   `json:"tunnel_ip_address"`
	WireguardPublicKey string   `json:"wireguard_public_key"`
	ExpirationTime     int64    `json:"expiration_time"`
	CreatedAt          int64    `json:"created_at"`
	UpdatedAt          int64    `json:"updated_at"`
	ServiceTunnelID    string   `json:"service_tunnel_id"`
}

func (edtc EnduserDeviceTunnelConfigInfo) UniqueID() string {
	return edtc.ID
}
