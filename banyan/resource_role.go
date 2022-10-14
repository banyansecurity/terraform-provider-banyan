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
		Description:   "A role represents a group of users in the organization.",
		CreateContext: resourceRoleCreate,
		ReadContext:   resourceRoleRead,
		UpdateContext: resourceRoleUpdate,
		DeleteContext: resourceRoleDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
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
			"service_accounts": {
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
				Description: "Name of the group (from your IdP) which will be included in the role",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"email": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Description: "Email address for the user or group of users in the role",
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
		},
	}
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
			ServiceAccts:    convertSchemaSetToStringSlice(d.Get("service_accounts").(*schema.Set)),
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
		diag.FromErr(err)
		return
	}
	d.SetId(resp.ID)
	return
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourceRoleCreate(ctx, d, m)
	return
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Role.Get(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	d.Set("name", resp.Name)
	d.Set("description", resp.Description)
	d.Set("container_fqdn", resp.UnmarshalledSpec.Spec.ContainerFQDN)
	d.Set("image", resp.UnmarshalledSpec.Spec.Image)
	d.Set("repo_tag", resp.UnmarshalledSpec.Spec.RepoTag)
	d.Set("user_group", resp.UnmarshalledSpec.Spec.UserGroup)
	d.Set("email", resp.UnmarshalledSpec.Spec.Email)
	d.Set("device_ownership", resp.UnmarshalledSpec.Spec.DeviceOwnership)
	d.Set("platform", resp.UnmarshalledSpec.Spec.Platform)
	d.Set("known_device_only", resp.UnmarshalledSpec.Spec.KnownDeviceOnly)
	d.Set("mdm_present", resp.UnmarshalledSpec.Spec.MDMPresent)
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
