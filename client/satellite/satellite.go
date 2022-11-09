package satellite

import (
	"encoding/json"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type Satellite struct {
	restClient *restclient.Client
}

const apiVersion = "api/v2"
const component = "satellite"

func NewClient(restClient *restclient.Client) Client {
	satelliteClient := Satellite{
		restClient: restClient,
	}
	return &satelliteClient
}

type Client interface {
	Get(id string) (satellite SatelliteTunnelConfig, err error)
	Create(satellite Info) (created SatelliteTunnelConfig, err error)
	Update(id string, satellite Info) (updated SatelliteTunnelConfig, err error)
	Delete(id string) (err error)
}

func (s *Satellite) Get(id string) (satellite SatelliteTunnelConfig, err error) {
	resp, err := s.restClient.Read(apiVersion, component, id, "")
	var j SatelliteTunnelResponse
	err = json.Unmarshal(resp, &j)
	satellite = j.Data
	return
}

func (s *Satellite) Create(satellite Info) (created SatelliteTunnelConfig, err error) {
	body, err := json.Marshal(satellite)
	if err != nil {
		return
	}
	resp, err := s.restClient.Create(apiVersion, component, body, "")
	var j SatelliteTunnelResponse
	err = json.Unmarshal(resp, &j)
	created = j.Data
	return
}

func (s *Satellite) Update(id string, satellite Info) (updated SatelliteTunnelConfig, err error) {
	body, err := json.Marshal(satellite)
	if err != nil {
		return
	}
	resp, err := s.restClient.Update(apiVersion, component, id, body, "")
	var j SatelliteTunnelResponse
	err = json.Unmarshal(resp, &j)
	updated = j.Data
	return
}

func (s *Satellite) Delete(id string) (err error) {
	err = s.restClient.Delete(apiVersion, component, id, "")
	return
}
