package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

func (this *Service) Get(id string) (service GetServiceSpec, ok bool, err error) {
	log.Printf("[SVC|CLIENT|GET] getting service with id: %q", id)
	if id == "" {
		err = errors.New("need an id to get a service")
		return
	}
	path := "api/v1/registered_services"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
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
	// Unmarshal the response into a service spec
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var createdServiceJson []GetServicesJson
	err = json.Unmarshal(responseData, &createdServiceJson)
	if err != nil {
		return
	}
	if len(createdServiceJson) == 0 {
		return
	}
	if len(createdServiceJson) > 1 {
		err = errors.New("got more than one service")
		return
	}
	createdServiceJson[0].ServiceSpec = html.UnescapeString(createdServiceJson[0].ServiceSpec)
	var createdSpec CreateService
	err = json.Unmarshal([]byte(createdServiceJson[0].ServiceSpec), &createdSpec)
	if err != nil {
		return
	}
	createdServiceJson[0].CreateServiceSpec = createdSpec
	service = mapToGetServiceSpec(createdServiceJson[0])
	ok = true
	log.Printf("[SVC|CLIENT|GET] got service with id: %q", id)
	return
}

func (this *Service) disable(id string) (err error) {
	log.Printf("[SVC|CLIENT|DISABLE] disabling service id: %q", id)
	path := "api/v1/disable_registered_service"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
	resp, err := this.restClient.DoPost(myUrl.String(), nil)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v", resp))
		return
	}
	log.Printf("[SVC|CLIENT|DISABLE] disabled service id: %q", id)
	return
}

func (this *Service) Delete(id string) (err error) {
	log.Printf("[SVC|CLIENT|DELETE] delete service id: %q", id)
	err = this.disable(id)
	if err != nil {
		log.Printf("Couldn't disable service: %s before delete", id)
	}
	path := "api/v1/delete_registered_service"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
	resp, err := this.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		responseData, _ := ioutil.ReadAll(resp.Body)
		// should clean this up to say everything, but recording the bnn-request-id header is useful.
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %#v with message: %s", resp, string(responseData)))
		return
	}
	log.Printf("[SVC|CLIENT|DELETE] deleted service id: %q", id)
	return
}

func (this *Service) Create(svc CreateService) (service GetServiceSpec, err error) {
	path := "api/v1/insert_registered_service"
	log.Printf("[SVC|CLIENT|CREATE] Creating a new service %#v\n", svc)
	toCreateSpec, err := json.MarshalIndent(svc, "", "   ")
	log.Printf("[SVC|CLIENT|GET] retrieved spec\n %s", string(toCreateSpec))
	body, err := json.Marshal(svc)
	if err != nil {
		log.Printf("[SVC|CLIENT|DELETE] marshaling a service to json, found an error %#v\n", err)
		return
	}
	request, err := this.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[SVC|CLIENT|CREATE] Creating a new service request, found an error %#v\n", err)
		return
	}
	log.Printf("[SVC|CLIENT|CREATE] %#v", request.URL)
	response, err := this.restClient.Do(request)
	if err != nil {
		log.Printf("[SVC|CLIENT|CREATE] when sending request status code %#v, found an error %#v\n", response.StatusCode, err)
		return
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("[SVC|CLIENT|CREATE] status code %#v, found an error when reading body %#v\n", response.StatusCode, err)
	}
	if response.StatusCode != 200 {
		log.Printf("[SVC|CLIENT|CREATE] status code %#v, found an error %#v, message: %s\n", response.StatusCode, err, string(responseData))
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to create service, message: %s", response.Status, response, string(responseData)))
		return
	}
	log.Printf("[SVC|CLIENT|CREATE] Created a new service %#v\n", string(responseData))
	var getServicesJson GetServicesJson
	err = json.Unmarshal(responseData, &getServicesJson)
	if err != nil {
		return
	}
	getServicesJson.ServiceSpec = html.UnescapeString(getServicesJson.ServiceSpec)
	var createdService CreateService
	err = json.Unmarshal([]byte(getServicesJson.ServiceSpec), &createdService)
	if err != nil {
		return
	}
	getServicesJson.Spec = createdService.Spec
	service = mapToGetServiceSpec(getServicesJson)
	createdSpec, err := json.MarshalIndent(service, "", "   ")
	log.Printf("[SVC|CLIENT|CREATE] created spec\n %s", string(createdSpec))
	return
}

func (this *Service) Update(id string, svc CreateService) (service GetServiceSpec, err error) {
	log.Printf("[SVC|CLIENT|UPDATE] updating service")
	service, err = this.Create(svc)
	log.Printf("[SVC|CLIENT|UPDATE] updated service")
	return
}

func mapToGetServiceSpec(original GetServicesJson) (new GetServiceSpec) {
	new = GetServiceSpec{
		ClusterName:       original.ClusterName,
		ServiceID:         original.ServiceID,
		ServiceName:       original.ServiceName,
		ServiceType:       original.ServiceType,
		ServiceDiscovery:  original.ServiceDiscovery,
		ServiceVersion:    original.ServiceVersion,
		Description:       original.Description,
		CreatedBy:         original.CreatedBy,
		CreatedAt:         original.CreatedAt,
		LastUpdatedBy:     original.LastUpdatedBy,
		LastUpdatedAt:     original.LastUpdatedAt,
		DeletedBy:         original.DeletedBy,
		DeletedAt:         original.DeletedAt,
		External:          original.External,
		OIDCEnabled:       original.OIDCEnabled,
		OIDCClientSpec:    original.OIDCClientSpec,
		UserFacing:        original.UserFacing,
		Protocol:          original.Protocol,
		Domain:            original.Domain,
		Port:              original.Port,
		Enabled:           original.Enabled,
		IsDefault:         original.IsDefault,
		Spec:              original.Spec,
		CreateServiceSpec: original.CreateServiceSpec,
	}
	return
}
