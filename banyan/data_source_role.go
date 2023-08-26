package banyan

import (
	"context"

	"github.com/pkg/errors"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRoleSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role",
		},
		"description": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Description of the role",
		},
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the role in Banyan",
		},
		"container_fqdn": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "FQDN for the container",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"image": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "Image",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"repo_tag": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "Repo Tag",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"service_account": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "Service accounts to be included in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"user_group": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "Names of the groups (from your IdP) which will be included in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"email": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "Email addresses for the users in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"device_ownership": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "Device ownership specification for the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"platform": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "Platform type which is required by the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"known_device_only": {
			Type:        schema.TypeBool,
			Computed:    true,
			Description: "Enforces whether the role requires known devices only for access",
		},
		"mdm_present": {
			Type:        schema.TypeBool,
			Computed:    true,
			Description: "Enforces whether the role requires an MDM to be present on the device",
		},
	}
	return
}

func dataSourceRole() *schema.Resource {
	return &schema.Resource{
		Description: "Obtains information describing the role from banyan",
		ReadContext: dataSourceRoleRead,
		Schema:      dataSourceRoleSchema(),
	}
}

func dataSourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Role.GetName(d.Get("name").(string))
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	if resp.ID == "" {
		err = errors.New("Could not find role with name: " + d.Get("name").(string))
		return diag.FromErr(err)
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
