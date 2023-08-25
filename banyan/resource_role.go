package banyan

import (
	"context"

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
			Computed:    true,
			Description: "FQDN for the container",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"image": {
			Type:        schema.TypeSet,
			Optional:    true,
			Computed:    true,
			Description: "Image",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"repo_tag": {
			Type:        schema.TypeSet,
			Optional:    true,
			Computed:    true,
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
			Computed:    true,
			Description: "Names of the groups (from your IdP) which will be included in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"email": {
			Type:        schema.TypeSet,
			Optional:    true,
			Computed:    true,
			Description: "Email addresses for the users in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"device_ownership": {
			Type:        schema.TypeSet,
			Optional:    true,
			Computed:    true,
			Description: "Device ownership specification for the role",
			Elem: &schema.Schema{
				Type:         schema.TypeString,
				ValidateFunc: validation.StringInSlice([]string{"Corporate Dedicated", "Corporate Shared", "Employee Owned", "Other"}, false),
			},
		},
		"platform": {
			Type:        schema.TypeSet,
			Optional:    true,
			Computed:    true,
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
		APIVersion: "rbac.banyanops.com/v1",
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
		},
	}
	return
}

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Role.Create(RoleFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	return
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Role.Update(RoleFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	return
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Role.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	d.SetId(resp.ID)
	err = d.Set("name", resp.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", resp.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("container_fqdn", resp.UnmarshalledSpec.Spec.ContainerFQDN)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("image", resp.UnmarshalledSpec.Spec.Image)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("repo_tag", resp.UnmarshalledSpec.Spec.RepoTag)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("user_group", resp.UnmarshalledSpec.Spec.UserGroup)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("email", resp.UnmarshalledSpec.Spec.Email)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("device_ownership", resp.UnmarshalledSpec.Spec.DeviceOwnership)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("platform", resp.UnmarshalledSpec.Spec.Platform)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("known_device_only", resp.UnmarshalledSpec.Spec.KnownDeviceOnly)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("mdm_present", resp.UnmarshalledSpec.Spec.MDMPresent)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.Role.Delete(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return
}
