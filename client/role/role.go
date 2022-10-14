package role

import (
	"encoding/json"
	"errors"
	"github.com/banyansecurity/terraform-banyan-provider/client/crud"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"html"
	"net/url"
)

const apiVersion = "api/v1"
const component = "security_roles"

type Role struct {
	restClient *restclient.RestClient
}

// NewClient returns a new client for interacting with the role resource
func NewClient(restClient *restclient.RestClient) Client {
	c := Role{
		restClient: restClient,
	}
	return &c
}

type Client interface {
	Get(id string) (role GetRole, err error)
	Create(role CreateRole) (created GetRole, err error)
	Update(role CreateRole) (updated GetRole, err error)
	Delete(id string) (err error)
	disable(id string) (err error)
}

// disable is used to disable a role. This is required before deleting a role.
func (r *Role) disable(id string) (err error) {
	if id == "" {
		err = errors.New("need an id disable a role")
		return
	}
	path := "api/v1/disable_security_role"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	query.Set("RoleID", id)
	myUrl.RawQuery = query.Encode()
	response, err := r.restClient.DoPost(myUrl.String(), nil)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		err = errors.New(response.Status)
		return
	}
	return
}

func (r *Role) Get(id string) (role GetRole, err error) {
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
	resp, err := crud.GetQuery(r.restClient, component, id, query, path)
	var j []GetRole
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	if len(j) == 0 {
		err = errors.New("role not found")
		return
	}
	if len(j) > 1 {
		err = errors.New("got more than one role")
		return
	}
	role = j[0]
	sSpec := html.UnescapeString(j[0].Spec)
	err = json.Unmarshal([]byte(sSpec), &role.UnmarshalledSpec)
	if err != nil {
		return
	}
	return

}

func (r *Role) Create(role CreateRole) (created GetRole, err error) {
	path := "api/v1/insert_security_role"
	body, err := json.Marshal(role)
	if err != nil {
		return
	}
	resp, err := crud.Create(r.restClient, apiVersion, component, body, path)
	err = json.Unmarshal(resp, &created)
	if err != nil {
		return
	}
	sSpec := html.UnescapeString(created.Spec)
	err = json.Unmarshal([]byte(sSpec), &created.UnmarshalledSpec)
	return
}

func (r *Role) Update(role CreateRole) (updatedRole GetRole, err error) {
	updatedRole, err = r.Create(role)
	if err != nil {
		return
	}
	return
}

// Delete will disable the role and then delete it
func (r *Role) Delete(id string) (err error) {
	err = r.disable(id)
	if err != nil {
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
	err = crud.DeleteQuery(r.restClient, component, id, query, path)
	return
}
