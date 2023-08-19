package role

import (
	"encoding/json"
	"errors"
	"html"
	"net/url"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

const apiVersion = "api/v1"
const component = "security_roles"

type Role struct {
	restClient *restclient.Client
}

// NewClient returns a new client for interacting with the role resource
func NewClient(restClient *restclient.Client) Client {
	c := Role{
		restClient: restClient,
	}
	return &c
}

type Client interface {
	Get(id string) (role GetRole, err error)
	GetName(name string) (role GetRole, err error)
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
	resp, err := r.restClient.ReadQuery(component, query, path)
	if err != nil {
		return
	}
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
	resp, err := r.restClient.Create(apiVersion, component, body, path)
	if err != nil {
		return
	}
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
	err = r.restClient.DeleteQuery(component, id, query, path)
	return
}

func (r *Role) GetName(name string) (spec GetRole, err error) {
	specs, err := r.GetAll()
	if err != nil {
		return
	}
	spec, err = findByName(name, specs)
	return
}

func (r *Role) GetAll() (specs []GetRole, err error) {
	path := "api/v1/security_roles"
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	query := myUrl.Query()
	resp, err := r.restClient.ReadQuery(component, query, path)
	if err != nil {
		return
	}
	err = json.Unmarshal(resp, &specs)
	if err != nil {
		return
	}
	return
}

func findByName(name string, specs []GetRole) (spec GetRole, err error) {
	for _, s := range specs {
		if s.Name == name {
			return s, nil
		}
	}
	return
}
