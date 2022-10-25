package service

import (
	"encoding/json"
	"github.com/banyansecurity/terraform-banyan-provider/client/crud"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/pkg/errors"
	"html"
	"log"
	"net/url"
)

const apiVersion = "api/v1"
const component = "service"

func (s *Service) Get(id string) (service GetServiceSpec, err error) {
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
	resp, err := crud.ReadQuery(s.restClient, component, query, path)
	var createdServiceJson []GetServicesJson
	err = json.Unmarshal(resp, &createdServiceJson)
	if err != nil {
		return
	}
	if len(createdServiceJson) == 0 {
		err = errors.New("service not found")
		return
	}
	if len(createdServiceJson) > 1 {
		err = errors.New("multiple services with same ID")
		return
	}
	createdServiceJson[0].ServiceSpec = html.UnescapeString(createdServiceJson[0].ServiceSpec)
	var createdSpec CreateService
	err = json.Unmarshal([]byte(createdServiceJson[0].ServiceSpec), &createdSpec)
	if err != nil {
		return
	}
	createdServiceJson[0].CreateServiceSpec = createdSpec
	return MapToGetServiceSpec(createdServiceJson[0]), nil
}

func (s *Service) Disable(id string) (err error) {
	path := "api/v1/disable_registered_service"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
	resp, err := s.restClient.DoPost(myUrl.String(), nil)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.Errorf("could not disable service with id: %s", id)
		return
	}
	log.Printf("disabled service: %q", id)
	return
}

func (s *Service) Delete(id string) (err error) {
	err = s.Disable(id)
	if err != nil {
		return
	}
	path := "api/v1/delete_registered_service"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
	err = crud.DeleteQuery(s.restClient, "service", id, query, path)
	log.Printf("deleted service: %q", id)
	return
}

func (s *Service) DetachPolicy(serviceID string) (err error) {
	c := policyattachment.NewClient(s.restClient)
	policyAtt, err := c.Get(serviceID, "service")
	if err != nil {
		return
	}
	_ = c.DeleteServiceAttachment(policyAtt.PolicyID, serviceID)
	return
}

func (s *Service) Create(spec CreateService) (created GetServiceSpec, err error) {
	path := "api/v1/insert_registered_service"
	body, err := json.Marshal(spec)
	if err != nil {
		return
	}
	resp, err := crud.Create(s.restClient, apiVersion, component, body, path)
	if err != nil {
		return
	}
	var j GetServicesJson
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	j.ServiceSpec = html.UnescapeString(j.ServiceSpec)
	var createdService CreateService
	err = json.Unmarshal([]byte(j.ServiceSpec), &createdService)
	if err != nil {
		return
	}
	j.Spec = createdService.Spec
	return MapToGetServiceSpec(j), nil
}

func (s *Service) Update(id string, spec CreateService) (updated GetServiceSpec, err error) {
	updated, err = s.Create(spec)
	if err != nil {
		err = errors.Errorf("could not update service: %s", id)
	}
	return
}

func MapToGetServiceSpec(original GetServicesJson) (new GetServiceSpec) {
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
