package satellite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type SatelliteStatus string

const (
	Unknown          SatelliteStatus = "Unknown"
	Pending          SatelliteStatus = "Pending"
	Healthy          SatelliteStatus = "Healthy"
	PartiallyHealthy SatelliteStatus = "PartiallyHealthy"
	UnHealthy        SatelliteStatus = "Unhealthy"
	InActive         SatelliteStatus = "Inactive"
	Terminated       SatelliteStatus = "Terminated"
)

const DefaultName = "default-connector"

type SatelliteTunnelConfig struct {
	ID                  string       `json:"id"`
	OrgID               string       `json:"org_id"`
	Name                string       `json:"name"`
	DisplayName         string       `json:"display_name"`
	TunnelIPAddress     string       `json:"tunnel_ip_address"`
	Keepalive           int64        `json:"keepalive"`
	Status              string       `json:"status,omitempty"`
	WireguardPublicKey  string       `json:"wireguard_public_key"`
	WireguardPrivateKey string       `json:"wireguard_private_key,omitempty"`
	CIDRs               []string     `json:"cidrs"`
	AccessTiers         []AccessTier `json:"access_tiers"`
	CreatedAt           int64        `json:"created_at,omitempty"`
	UpdatedAt           int64        `json:"updated_at,omitempty"`
	APIKeyID            string       `json:"api_key_id,omitempty"`
	ConnectorVersion    string       `json:"connector_version,omitempty"`
	HostInfo            *HostInfo    `json:"host_info,omitempty"`
	LastStatusUpdatedAt int64        `json:"-"`
	SSHCAPublicKey      string       `json:"ssh_ca_public_key,omitempty"`
	CreatedBy           string       `json:"created_by"`
	UpdatedBy           string       `json:"updated_by"`
	Spec                string       `json:"spec"`
}

type AccessTier struct {
	SatelliteTunnelPeerID string `json:"satellite_tunnel_peer_id"`
	AccessTierID          string `json:"access_tier_id"`
	Healthy               *bool  `json:"healthy,omitempty"`
	WireguardPublicKey    string `json:"wireguard_public_key,omitempty"`
	Endpoint              string `json:"endpoint,omitempty"`
	AllowedIPs            string `json:"allowed_ips,omitempty"`
	AccessTierName        string `json:"access_tier_name,omitempty"`
}

type SatellitePeerStatus struct {
	AccessTierID       string `json:"access_tier_id"`
	Healthy            *bool  `json:"healthy"`
	WireguardPublicKey string `json:"wireguard_public_key"`
	Endpoint           string `json:"endpoint"`
	AllowedIPs         string `json:"allowed_ips"`
	LatestHandshake    string `json:"latest_handshake"`
	Transfer           string `json:"transfer"`
}

type HostInfo struct {
	Name        string   `json:"name"`
	IPAddresses []string `json:"ip_addresses"`
}

type PeersStatus struct {
	ConnectorVersion *string               `json:"connector_version,omitempty"`
	HostInfo         *HostInfo             `json:"host_info,omitempty"`
	Peers            []SatellitePeerStatus `json:"peers"`
}

func (s *SatelliteTunnelConfig) Sanitize() {
	s.WireguardPrivateKey = ""
}

type Info struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api_version"`
	Type       string `json:"type"` //attribute
	Metadata   `json:"metadata"`
	Spec       `json:"spec"`
}

type Metadata struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type Spec struct {
	APIKeyID        string           `json:"api_key_id"`
	Keepalive       int64            `json:"keepalive"`
	CIDRs           []string         `json:"cidrs"`
	PeerAccessTiers []PeerAccessTier `json:"peer_access_tiers"`
}

type PeerAccessTier struct {
	Cluster     string   `json:"cluster"`
	AccessTiers []string `json:"access_tiers"`
}

type Satellite struct {
	restClient *restclient.RestClient
}

// NewClient returns a new client for interacting with the satellite resource
func NewClient(restClient *restclient.RestClient) SatelliteClienter {
	satelliteClient := Satellite{
		restClient: restClient,
	}
	return &satelliteClient
}

// SatelliteClienter is used for performing CRUD operations on the satellite resource
type SatelliteClienter interface {
	Get(id string) (satellite SatelliteTunnelConfig, ok bool, err error)
	Create(satellite Info) (createdSatellite SatelliteTunnelConfig, err error)
	Update(satellite Info) (updatedSatellite SatelliteTunnelConfig, err error)
	Delete(id string) (err error)
	disable(id string) (err error)
}

// disable is used to disable a satellite. This is required before deleting a satellite.
func (this *Satellite) disable(id string) (err error) {
	if id == "" {
		err = errors.New("need an id disable a satellite")
		return
	}
	log.Printf("[SATELLITE|DISABLE] disabling satellite: %v", id)
	path := "api/v1/disable_security_satellite"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("SatelliteID", id)
	myUrl.RawQuery = query.Encode()
	response, err := this.restClient.DoPost(myUrl.String(), nil)
	if err != nil {
		log.Printf("[POLICY|POST] status code %#v, found an error %#v\n", response.StatusCode, err)
		return
	}
	if response.StatusCode != 200 {
		defer response.Body.Close()
		responseBody, rerr := ioutil.ReadAll(response.Body)
		if rerr != nil {
			err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to disable satellite id: %q, couldn't parse body got error %+v", response.Status, response, id, rerr))
			return
		}
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to disable satellite id: %q, has message: %v", response.Status, response, id, string(responseBody)))
		return
	}
	log.Printf("[SATELLITE|DISABLE] disabled satellite: %v", id)
	return
}

func (this *Satellite) Get(id string) (satellite SatelliteTunnelConfig, ok bool, err error) {
	log.Printf("[SATELLITE|GET] reading satellite")
	if id == "" {
		err = errors.New("need an id to get a satellite")
		return
	}
	path := "/experimental/v2/satellite"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := this.restClient.DoGet(myUrl.String())
	if err != nil {
		return
	}
	if response.StatusCode == 404 || response.StatusCode == 400 {
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
	var getSatelliteJson []SatelliteTunnelConfig
	err = json.Unmarshal(responseData, &getSatelliteJson)
	if err != nil {
		return
	}
	if len(getSatelliteJson) == 0 {
		err = errors.New(fmt.Sprintf("could not find satellite with id %s", id))
		return
	}
	for i := range getSatelliteJson {
		if getSatelliteJson[i].ID == id {
			satellite = getSatelliteJson[i]
		}
	}
	var spec Info
	err = json.Unmarshal([]byte(satellite.Spec), &spec)
	if err != nil {
		return
	}
	log.Printf("[POLICY|GET] read satellite")
	return
}

func (this *Satellite) Create(satellite Info) (createdSatellite SatelliteTunnelConfig, err error) {
	path := "api/experimental/v2/satellite"
	body, err := json.Marshal(satellite)
	if err != nil {
		log.Printf("[SATELLITE|POST] Creating a new satellite, found an error %#v\n", err)
		return
	}
	request, err := this.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[SATELLITE|POST] Creating a new request, found an error %#v\n", err)
		return
	}
	response, err := this.restClient.Do(request)
	if response.StatusCode != 200 {
		log.Printf("[SATELLITE|POST] status code %#v, found an error %#v\n", response.StatusCode, err)
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(responseData, &createdSatellite)
	if err != nil {
		return
	}
	log.Printf("[SATELLITE|POST] created a new satellite %#v", createdSatellite)
	return
}

func (this *Satellite) Update(satellite Info) (updatedSatellite SatelliteTunnelConfig, err error) {
	log.Printf("[SATELLITE|UPDATE] updating satellite")
	updatedSatellite, err = this.Create(satellite)
	if err != nil {
		return
	}
	log.Printf("[SATELLITE|UPDATE] updated satellite")
	return
}

// Delete will disable the satellite and then delete it
func (this *Satellite) Delete(id string) (err error) {
	log.Printf("[SATELLITE|DELETE] deleting satellite with id %s", id)
	path := "/experimental/v2/satellite/"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("id", id)
	myUrl.RawQuery = query.Encode()
	resp, err := this.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v", resp))
		return
	}
	log.Printf("[SATELLITE|DELETE] deleted satellite with id %s", id)
	return
}
