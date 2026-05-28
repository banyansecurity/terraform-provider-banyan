package banyan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// The role resource. For more information on Banyan roles, please see the documentation:
func resourceRole() *schema.Resource {
	return &schema.Resource{
		Description:   "The role resource represents a group of users in the organization. For more information on Banyan roles, see the [documentation.](https://docs.banyansecurity.io/docs/feature-guides/administer-security-policies/roles/manage-roles/)",
		CreateContext: resourceRoleCreate,
		ReadContext:   resourceRoleRead,
		UpdateContext: resourceRoleUpdate,
		DeleteContext: resourceRoleDelete,
		Schema:        RoleSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func RoleSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Name of the role",
		},
		"description": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Description of the role",
		},
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the role in Banyan",
		},
		"container_fqdn": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "FQDN for the container",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"image": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Image",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"repo_tag": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Repo Tag",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"service_account": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Service accounts to be included in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"user_group": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Names of the groups (from your IdP) which will be included in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"email": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Email addresses for the users in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"device_ownership": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Device ownership specification for the role",
			Elem: &schema.Schema{
				Type:         schema.TypeString,
				ValidateFunc: validation.StringInSlice([]string{"Corporate Dedicated", "Corporate Shared", "Employee Owned", "Other"}, false),
			},
		},
		"platform": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Platform type which is required by the role",
			Elem: &schema.Schema{
				Type:         schema.TypeString,
				ValidateFunc: validation.StringInSlice([]string{"Windows", "macOS", "Linux", "iOS", "Android", "Unregistered"}, false),
			},
		},
		"known_device_only": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enforces whether the role requires known devices only for access",
		},
		"mdm_present": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enforces whether the role requires an MDM to be present on the device",
		},
		"serial_numbers": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of Serial Numbers belonging to devices for the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"api_version": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "defines version of API to use v1/v2",
			Default:     role.DefaultAPIVersion,
		},
	}
	return
}

func RoleFromState(d *schema.ResourceData) (r role.CreateRole) {
	r = role.CreateRole{
		Metadata: role.Metadata{
			ID:          d.Get("id").(string),
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			Tags: role.Tags{
				Template: "USER",
			},
		},
		Kind:       "BanyanRole",
		APIVersion: fmt.Sprintf("rbac.banyanops.com/%s", d.Get("api_version").(string)),
		Type:       "origin",
		Spec: role.Spec{
			ContainerFQDN:   convertSchemaSetToStringSlice(d.Get("container_fqdn").(*schema.Set)),
			Image:           convertSchemaSetToStringSlice(d.Get("image").(*schema.Set)),
			RepoTag:         convertSchemaSetToStringSlice(d.Get("repo_tag").(*schema.Set)),
			LabelSelector:   []role.LabSel{},
			ServiceAccts:    convertSchemaSetToStringSlice(d.Get("service_account").(*schema.Set)),
			UserGroup:       convertSchemaSetToStringSlice(d.Get("user_group").(*schema.Set)),
			Email:           convertSchemaSetToStringSlice(d.Get("email").(*schema.Set)),
			DeviceOwnership: convertSchemaSetToStringSlice(d.Get("device_ownership").(*schema.Set)),
			Platform:        convertSchemaSetToStringSlice(d.Get("platform").(*schema.Set)),
			KnownDeviceOnly: d.Get("known_device_only").(bool),
			MDMPresent:      d.Get("mdm_present").(bool),
			SerialNumbers:   convertSchemaSetToStringSlice(d.Get("serial_numbers").(*schema.Set)),
		},
	}
	return
}

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)

	apiVersion := d.Get("api_version").(string)
	var id string

	switch apiVersion {
	case "v1":
		resp, err := c.Role.Create(RoleFromState(d))
		if err != nil {
			return diag.FromErr(err)
		}
		id = resp.ID
	case "v2":
		resp, err := c.RoleV2.CreateRole(RoleFromState(d))
		if err != nil {
			return diag.FromErr(err)
		}
		id = resp.ID
	}

	d.SetId(id)

	return
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)

	apiVersion := d.Get("api_version").(string)
	var id string

	switch apiVersion {
	case "v1":
		resp, err := c.Role.Update(RoleFromState(d))
		if err != nil {
			log.Printf("[ERROR] API error: %v", err)
			return diag.FromErr(err)
		}
		id = resp.ID
	case "v2":
		resp, err := c.RoleV2.UpdateRole(RoleFromState(d))
		if err != nil {
			return diag.FromErr(err)
		}
		id = resp.ID
	}

	d.SetId(id)

	return
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)

	apiVersion := d.Get("api_version").(string)

	var id, name, description string
	var spec role.CreateRole

	//when we import existing resource it doesn't use default value
	if apiVersion == "" {
		apiVersion = role.DefaultAPIVersion
	}

	switch apiVersion {
	case "v1":
		resp, err := c.Role.Get(d.Id())
		if err != nil {
			handleNotFoundError(d, err)
			return
		}

		id = resp.ID
		name = resp.Name
		description = resp.Description
		spec = resp.UnmarshalledSpec

	case "v2":
		resp, err := c.RoleV2.GetRole(d.Id())
		if err != nil {
			return diag.FromErr(err)
		}

		err = json.Unmarshal([]byte(resp.Spec), &spec)
		if err != nil {
			return diag.FromErr(err)
		}

		id = resp.ID
		name = resp.Name
		description = resp.Description
	default:
		err := fmt.Errorf("Invalid Version of API %s", apiVersion)
		return diag.FromErr(err)
	}

	d.SetId(id)

	err := d.Set("name", name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", description)
	if err != nil {
		return diag.FromErr(err)
	}

	err = role.SetRoleStateFromSpec(d, spec)
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)

	apiVersion := d.Get("api_version").(string)

	switch apiVersion {
	case "v1":
		err := c.Role.Delete(d.Id())
		if err != nil {
			return diag.FromErr(err)
		}
	case "v2":
		err := c.RoleV2.DeleteRole(d.Id())
		if err != nil {
			return diag.FromErr(err)
		}
	}

	d.SetId("")
	return
}
