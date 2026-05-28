package role

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

const apiVersionV2 = "api/v2"
const securityRolePath = "security_roles"

type RoleV2 struct {
	restClient *restclient.Client
}

// NewClient returns a new client for interacting with the role resource
func NewClientV2(restClient *restclient.Client) ClientV2 {
	c := RoleV2{
		restClient: restClient,
	}
	return &c
}

type ClientV2 interface {
	GetRole(id string) (role V2SecurityRoleInfo, err error)
	CreateRole(role CreateRole) (created V2SecurityRoleInfo, err error)
	UpdateRole(role CreateRole) (updated V2SecurityRoleInfo, err error)
	DeleteRole(id string) (err error)
	GetByName(name string) (role V2SecurityRoleInfo, err error)
}

func (r *RoleV2) GetRole(id string) (role V2SecurityRoleInfo, err error) {

	response, err := r.restClient.Read(apiVersionV2, securityRolePath, id, "")
	if err != nil {
		return
	}

	var j V2Resp
	err = json.Unmarshal(response, &j)
	if err != nil {
		return
	}

	role = j.Data

	return

}

func (r *RoleV2) CreateRole(role CreateRole) (roleInfo V2SecurityRoleInfo, err error) {

	rolebytes, err := json.Marshal(role)
	if err != nil {
		return
	}

	response, err := r.restClient.Create(apiVersionV2, securityRolePath, rolebytes, "")
	if err != nil {
		err = fmt.Errorf("request to %s/%s failed %w", apiVersionV2, securityRolePath, err)
		return
	}

	var j V2Resp
	err = json.Unmarshal(response, &j)
	if err != nil {
		return
	}

	roleInfo = j.Data

	return
}

func (r *RoleV2) UpdateRole(role CreateRole) (updatedRole V2SecurityRoleInfo, err error) {
	body, err := json.Marshal(role)
	if err != nil {
		return
	}

	response, err := r.restClient.Update(apiVersionV2, component, role.Metadata.ID, body, "")
	if err != nil {
		return
	}

	var j V2Resp
	err = json.Unmarshal(response, &j)
	if err != nil {
		return
	}

	updatedRole = j.Data

	return
}

// Delete will disable the role and then delete it
func (r *RoleV2) DeleteRole(id string) (err error) {

	err = r.restClient.Delete(apiVersionV2, securityRolePath, id, "")
	if err != nil {
		return
	}

	return
}

func (r *RoleV2) GetByName(name string) (role V2SecurityRoleInfo, err error) {
	path := fmt.Sprintf("%s/%s", apiVersionV2, securityRolePath)
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}

	query := myUrl.Query()
	query.Set("name", name)
	myUrl.RawQuery = query.Encode()

	response, err := r.restClient.ReadQuery(component, query, path)
	if err != nil {
		return
	}

	var resp V2ListResp
	err = json.Unmarshal(response, &resp)
	if err != nil {
		return
	}

	if len(resp.Data.Roles) == 0 {
		err = fmt.Errorf("could not find role with name %s", name)
		return
	}

	role = resp.Data.Roles[0]

	return
}
