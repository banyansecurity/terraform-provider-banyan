package service

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/url"

	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/pkg/errors"
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
	resp, err := s.restClient.ReadQuery(component, query, path)
	if err != nil {
		return
	}
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
	err = s.updateService(id, path)
	if err != nil {
		return
	}
	log.Printf("disabled service: %q", id)
	return
}

func (s *Service) Enabled(id string) (err error) {
	path := "api/v1/enable_registered_service"
	err = s.updateService(id, path)
	if err != nil {
		return
	}
	log.Printf("enabled service: %q", id)
	return
}

func (s *Service) updateService(id, path string) (err error) {
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("ServiceID", id)
	myUrl.RawQuery = query.Encode()
	_, err = s.restClient.DoPost(myUrl.String(), nil)
	if err != nil {
		err = fmt.Errorf("error while enable/disable service %s", err)
	}
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
	err = s.restClient.DeleteQuery("service", id, query, path)
	if err != nil {
		err = fmt.Errorf("error deleting service %s", err)
	}
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
	// The API will always clobber, which leads to odd behavior
	// This aligns behavior with user expectations
	// Don't clobber if the service name already exist
	existing, err := s.GetByName(spec.Metadata.Name)
	if err != nil {
		return
	}
	if existing.ServiceID != "" {
		err = fmt.Errorf("the service name %s already exists", existing.ServiceName)
		return
	}

	resp, err := s.restClient.Create(apiVersion, component, body, path)
	log.Printf("[INFO] Created service %s", resp)
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
	log.Printf("[INFO] Created service %s", j.ServiceID)
	return MapToGetServiceSpec(j), nil
}

func (s *Service) Update(id string, spec CreateService) (updated GetServiceSpec, err error) {
	path := "api/v1/insert_registered_service"
	body, err := json.Marshal(spec)
	if err != nil {
		return
	}
	resp, err := s.restClient.Create(apiVersion, component, body, path)
	log.Printf("[INFO] Updated service %s", resp)
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
	log.Printf("[INFO] Updated service %s", id)
	return MapToGetServiceSpec(j), nil
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

// get policy for service
func (s *Service) GetPolicyForService(id string) (attachedPolicy policy.GetPolicy, err error) {
	paClient := policyattachment.NewClient(s.restClient)
	pClient := policy.NewClient(s.restClient)
	policyAtt, err := paClient.Get(id, "service")
	if err != nil {
		return
	}
	if policyAtt.PolicyID == "" {
		return
	}
	attachedPolicy, err = pClient.Get(policyAtt.PolicyID)
	return
}

func (s *Service) GetAll() (services []RegisteredServiceInfo, err error) {
	path := "api/v1/registered_services"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	resp, err := s.restClient.ReadQuery(component, query, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &services)
	if err != nil {
		return
	}
	return
}
func (s *Service) GetByName(name string) (service RegisteredServiceInfo, err error) {
	specs, err := s.GetAll()
	if err != nil {
		return
	}
	service, err = findByName(name, specs)
	return
}
func findByName(name string, specs []RegisteredServiceInfo) (spec RegisteredServiceInfo, err error) {
	for _, s := range specs {
		if s.ServiceName == name {
			return s, nil
		}
	}
	return
}
