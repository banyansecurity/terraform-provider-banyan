package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"log"
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
			"metadatatags": {
				Type:        schema.TypeList,
				MinItems:    0,
				MaxItems:    1,
				Optional:    true,
				Computed:    true,
				Description: "Metadata about the role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"template": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "USER",
							ValidateFunc: validateRoleTemplate(),
						},
					},
				},
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
				Description: "Repo Tag",
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
					Type: schema.TypeString,
				},
			},
			"platform": {
				Type:        schema.TypeSet,
				Optional:    true,
				Computed:    true,
				Description: "Platform type which is required by the role",
				Elem: &schema.Schema{
					Type: schema.TypeString,
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

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[ROLE|RES|CREATE] creating role %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	roleToCreate := role.CreateRole{
		Metadata: role.Metadata{
			ID:          d.Get("id").(string),
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			Tags: role.Tags{
				Template: d.Get("metadatatags.0.template").(string),
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
	createdRole, err := client.Role.Create(roleToCreate)
	if err != nil {
		diag.FromErr(errors.WithMessage(err, "couldn't create new role"))
		return
	}

	log.Printf("[ROLE|RES|CREATE] created role %s : %s", d.Get("name"), d.Id())
	d.SetId(createdRole.ID)
	diagnostics = resourceRoleRead(ctx, d, m)
	return
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[ROLE|RES|UPDATE] updating role %s : %s", d.Get("name"), d.Id())
	diagnostics = resourceRoleCreate(ctx, d, m)
	log.Printf("[ROLE|RES|UPDATE] updated role %s : %s", d.Get("name"), d.Id())
	return
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[ROLE|RES|READ] reading role %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	role, ok, err := client.Role.Get(id)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "couldn't get role with id: %s", id))
		return
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("role %q", d.Id()))
	}
	log.Printf("[ROLE|RES|READ] got role: %#v", role)
	d.Set("name", role.Name)
	d.Set("description", role.Description)
	d.Set("id", role.ID)
	d.Set("metadatatags", []interface{}{map[string]interface{}{
		"template": role.UnmarshalledSpec.Metadata.Tags.Template,
	}})
	d.Set("container_fqdn", role.UnmarshalledSpec.Spec.ContainerFQDN)
	d.Set("image", role.UnmarshalledSpec.Spec.Image)
	d.Set("repo_tag", role.UnmarshalledSpec.Spec.RepoTag)
	d.Set("user_group", role.UnmarshalledSpec.Spec.UserGroup)
	d.Set("email", role.UnmarshalledSpec.Spec.Email)
	d.Set("device_ownership", role.UnmarshalledSpec.Spec.DeviceOwnership)
	d.Set("platform", role.UnmarshalledSpec.Spec.Platform)
	d.Set("known_device_only", role.UnmarshalledSpec.Spec.KnownDeviceOnly)
	d.Set("mdm_present", role.UnmarshalledSpec.Spec.MDMPresent)
	log.Printf("[ROLE|RES|READ] read role %s : %s", d.Get("name"), d.Id())
	return
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[ROLE|RES|DELETE] deleting role %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	err := client.Role.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Printf("[ROLE|RES|DELETE] deleted role %s : %s", d.Get("name"), d.Id())
	return
}

func validateRoleTemplate() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v != "USER" && v != "" {
			errs = append(errs, fmt.Errorf("%q must be %q or \"\", got: %q", key, "USER", v))
		}
		return
	}
}
