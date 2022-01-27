package role

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type Role struct {
	restClient *restclient.RestClient
}

func NewClient(restClient *restclient.RestClient) RoleClienter {
	roleClient := Role{
		restClient: restClient,
	}
	return &roleClient
}

type RoleClienter interface {
	Get(id string) (role GetRole, ok bool, err error)
	Create(role CreateRole) (createdRole GetRole, err error)
	Update(role CreateRole) (updatedRole GetRole, err error)
	Delete(id string) (err error)
	disable(id string) (err error)
}

func (this *Role) disable(id string) (err error) {
	if id == "" {
		err = errors.New("need an id disable a role")
		return
	}
	log.Printf("[ROLE|DISABLE] disabling role: %v", id)
	path := "api/v1/disable_security_role"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("RoleID", id)
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
			err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to disable role id: %q, couldn't parse body got error %+v", response.Status, response, id, rerr))
			return
		}
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to disable role id: %q, has message: %v", response.Status, response, id, string(responseBody)))
		return
	}
	log.Printf("[ROLE|DISABLE] disabled role: %v", id)
	return
}

func (this *Role) Get(id string) (role GetRole, ok bool, err error) {
	log.Printf("[ROLE|GET] reading role")
	if id == "" {
		err = errors.New("need an id to get a role")
		return
	}
	path := "api/v1/security_roles"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("RoleID", id)
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

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	var getRoleJson []GetRole
	err = json.Unmarshal(responseData, &getRoleJson)
	if err != nil {
		return
	}
	if len(getRoleJson) == 0 {
		return
	}
	if len(getRoleJson) > 1 {
		err = errors.New("got more than one role")
		return
	}
	role = getRoleJson[0]
	role.Spec = html.UnescapeString(role.Spec)

	var spec CreateRole
	err = json.Unmarshal([]byte(role.Spec), &spec)
	if err != nil {
		return
	}

	role.UnmarshalledSpec = spec
	isEnabled, err := strconv.ParseBool(role.IsEnabledString)
	if err != nil {
		return
	}
	role.IsEnabled = isEnabled
	ok = true
	log.Printf("[POLICY|GET] read role")
	return

}

func (this *Role) Create(role CreateRole) (createdRole GetRole, err error) {
	path := "api/v1/insert_security_role"
	body, err := json.Marshal(role)
	if err != nil {
		log.Printf("[ROLE|POST] Creating a new role, found an error %#v\n", err)
		return
	}
	request, err := this.restClient.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[ROLE|POST] Creating a new request, found an error %#v\n", err)
		return
	}
	response, err := this.restClient.Do(request)
	if response.StatusCode != 200 {
		log.Printf("[ROLE|POST] status code %#v, found an error %#v\n", response.StatusCode, err)
		err = errors.New(fmt.Sprintf("unsuccessful, got status code %q with response: %+v for request to", response.Status, response))
		return
	}

	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(responseData, &createdRole)
	if err != nil {
		return
	}
	createdRole.Spec = html.UnescapeString(createdRole.Spec)
	var spec CreateRole
	err = json.Unmarshal([]byte(createdRole.Spec), &spec)
	if err != nil {
		return
	}
	createdRole.UnmarshalledSpec = spec
	isEnabled, err := strconv.ParseBool(createdRole.IsEnabledString)
	if err != nil {
		return
	}
	createdRole.IsEnabled = isEnabled
	log.Printf("[ROLE|POST] created a new role %#v", createdRole)
	return
}

func (this *Role) Update(role CreateRole) (updatedRole GetRole, err error) {
	log.Printf("[ROLE|UPDATE] updating role")
	updatedRole, err = this.Create(role)
	if err != nil {
		return
	}
	log.Printf("[ROLE|UPDATE] updated role")
	return
}

func (this *Role) Delete(id string) (err error) {
	log.Printf("[ROLE|DELETE] deleting role with id %s", id)
	err = this.disable(id)
	if err != nil {
		log.Printf("[ROLE|DELETE] couldn't disable role with id %s", id)
		return
	}
	path := "api/v1/delete_security_role"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("RoleID", id)
	myUrl.RawQuery = query.Encode()
	resp, err := this.restClient.DoDelete(myUrl.String())
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("didn't get a 200 status code instead got %v", resp))
		return
	}
	log.Printf("[ROLE|DELETE] deleted role with id %s", id)
	return
}
