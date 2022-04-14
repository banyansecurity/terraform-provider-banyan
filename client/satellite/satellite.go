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

type Satellite struct {
	restClient *restclient.RestClient
}

// NewClient returns a new client for interacting with the satellite resource
func NewClient(restClient *restclient.RestClient) Clienter {
	satelliteClient := Satellite{
		restClient: restClient,
	}
	return &satelliteClient
}

// SatelliteClienter is used for performing CRUD operations on the satellite resource
type Clienter interface {
	Get(id string) (satellite SatelliteTunnelConfig, err error)
	Create(satellite Info) (createdSatellite SatelliteTunnelConfig, err error)
	Update(satellite Info) (updatedSatellite SatelliteTunnelConfig, err error)
	Delete(id string) (err error)
}

func (s *Satellite) Get(id string) (satellite SatelliteTunnelConfig, err error) {
	log.Printf("[SATELLITE|GET] reading satellite")
	if id == "" {
		err = errors.New("need an id to get a satellite")
		return
	}
	path := fmt.Sprintf("api/experimental/v2/satellite/%s", id)
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := s.restClient.DoGet(myUrl.String())
	if err != nil {
		return
	}
	if response.StatusCode == 404 || response.StatusCode == 400 {
		err = errors.New(fmt.Sprintf("satellite with id %s not found", id))
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var getSatelliteJson SatelliteTunnelResponse
	err = json.Unmarshal(responseData, &getSatelliteJson)
	if err != nil {
		return
	}
	satellite = getSatelliteJson.Data
	if err != nil {
		return
	}
	log.Printf("[POLICY|GET] read satellite")
	return
}

func (s *Satellite) Create(satellite Info) (createdSatellite SatelliteTunnelConfig, err error) {
	path := "api/experimental/v2/satellite"
	body, err := json.Marshal(satellite)
	if err != nil {
		log.Printf("[SATELLITE|POST] Creating a new satellite, found an error %#v\n", err)
		return
	}
	request, err := s.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[SATELLITE|POST] Creating a new request, found an error %#v\n", err)
		return
	}
	response, err := s.restClient.Do(request)
	if response.StatusCode != 200 {
		log.Printf("[SATELLITE|POST] status code %#v, found an error %#v\n", response.StatusCode, err)
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	resonseJSON := SatelliteTunnelResponse{}
	err = json.Unmarshal(responseData, &resonseJSON)
	createdSatellite = resonseJSON.Data
	if err != nil {
		return
	}
	log.Printf("[SATELLITE|POST] created a new satellite %#v", createdSatellite)
	return
}

func (s *Satellite) Update(satellite Info) (updatedSatellite SatelliteTunnelConfig, err error) {
	log.Printf("[SATELLITE|UPDATE] updating satellite")
	updatedSatellite, err = s.Create(satellite)
	if err != nil {
		return
	}
	log.Printf("[SATELLITE|UPDATE] updated satellite")
	return
}

// Delete will disable the satellite and then delete it
func (s *Satellite) Delete(id string) (err error) {
	log.Printf("[SATELLITE|DELETE] deleting satellite with id %s", id)
	path := fmt.Sprintf("api/experimental/v2/satellite/%s", id)
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := s.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if response.StatusCode == 404 {
		err = errors.New(fmt.Sprintf("satellite with id %s not found", id))
		return
	}
	if response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to %s", response.Status, response.Request, path))
		return
	}
	log.Printf("[SATELLITE|DELETE] deleted satellite with id %s", id)
	return
}
