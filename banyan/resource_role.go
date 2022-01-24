package banyan

import (
	"context"
	"fmt"
	"log"
	"reflect"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

// The role resource. For more information on Banyan roles, please see the documentation:
func resourceRole() *schema.Resource {
	log.Println("[ROLE|RES] getting resource schema")
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
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "Metadata about the role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"template": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validateRoleTemplate(),
						},
					},
				},
			},
			"spec": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "The spec for the role",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"email": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "Email address for the user or group of users in the role",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"group": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "Name of the group (from your IdP) which will be included in the role",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"platform": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "Platform type which is required by the role",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"device_ownership": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "Device ownership specification for the role",
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
				},
			},
		},
	}
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

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[ROLE|RES|CREATE] creating role")
	client := m.(*client.ClientHolder)
	name, ok := d.Get("name").(string)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert name")
		return
	}
	description, ok := d.Get("description").(string)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert description")

		return
	}
	roleToCreate := role.CreateRole{
		Metadata: role.Metadata{
			Name:        name,
			Description: description,
		},
		Kind:       "BanyanRole",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
	}

	metadatatags, ok := d.Get("metadatatags").([]interface{})
	if !ok {
		metadatatags := reflect.TypeOf(d.Get("metadatatags"))
		diagnostics = diag.Errorf("Couldn't type assert metadatags, type is " + fmt.Sprintf("%+v", metadatatags))
		return
	}
	for _, item := range metadatatags {
		ii, ok := item.(map[string]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert element in metadatatags")
			return
		}

		roleToCreate.Metadata.Tags.Template, ok = ii["template"].(string)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert template")
			return
		}
	}

	spec, ok := d.Get("spec").([]interface{})
	if !ok {
		spec := reflect.TypeOf(d.Get("spec"))
		err := errors.New("Couldn't type assert spec, type is " + fmt.Sprintf("%+v", spec))
		diagnostics = diag.FromErr(err)
		return
	}
	for _, item := range spec {
		ii, ok := item.(map[string]interface{})
		if !ok {
			err := errors.New("Couldn't type assert element in spec")
			diagnostics = diag.FromErr(err)
			return
		}

		knownDeviceOnly, ok := ii["known_device_only"].(bool)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert known_device_only, got type: %v", reflect.TypeOf(ii["known_device_only"]))
			return
		}
		roleToCreate.Spec.KnownDeviceOnly = knownDeviceOnly

		mdmPresent, ok := ii["mdm_present"].(bool)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert mdm_present, got type: %v", reflect.TypeOf(ii["mdm_present"]))
			return
		}
		roleToCreate.Spec.MDMPresent = mdmPresent

		deviceOwnershipSet, ok := ii["device_ownership"].(*schema.Set)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert deviceOwnership, got type: %v", reflect.TypeOf(ii["device_ownership"]))
			return
		}
		for _, deviceOwnerShipOption := range deviceOwnershipSet.List() {
			deviceOwnerShipOptionValue, ok := deviceOwnerShipOption.(string)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert deviceOwnershipValue, got type: %v", reflect.TypeOf(deviceOwnerShipOption))
				return
			}
			roleToCreate.Spec.DeviceOwnership = append(roleToCreate.Spec.DeviceOwnership, deviceOwnerShipOptionValue)
		}

		emailSet, ok := ii["email"].(*schema.Set)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert email, got type: %v", reflect.TypeOf(ii["email"]))
			return
		}
		for _, email := range emailSet.List() {
			emailValue, ok := email.(string)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert email value, got type: %v", reflect.TypeOf(email))
				return
			}
			roleToCreate.Spec.Email = append(roleToCreate.Spec.Email, emailValue)
		}

		groupSet, ok := ii["group"].(*schema.Set)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert group, got type: %v", reflect.TypeOf(ii["group"]))
			return
		}
		for _, group := range groupSet.List() {
			groupValue, ok := group.(string)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert group value, got type: %v", reflect.TypeOf(group))
				return
			}
			roleToCreate.Spec.Group = append(roleToCreate.Spec.Group, groupValue)
		}

		platformSet, ok := ii["platform"].(*schema.Set)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert platform, got type: %v", reflect.TypeOf(ii["platform"]))
			return
		}
		for _, platform := range platformSet.List() {
			platformValue, ok := platform.(string)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert platform value, got type: %v", reflect.TypeOf(platform))
				return
			}
			roleToCreate.Spec.Platform = append(roleToCreate.Spec.Platform, platformValue)
		}
	}

	log.Printf("[ROLE|RES|CREATE] to be created %#v\n", roleToCreate)
	createdRole, err := client.Role.Create(roleToCreate)
	if err != nil {
		diag.FromErr(errors.WithMessage(err, "couldn't create new role"))
		return
	}
	log.Printf("[ROLE|RES|CREATE] createdRole %#v\n", createdRole)
	d.SetId(createdRole.ID)
	diagnostics = resourceRoleRead(ctx, d, m)
	return
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[ROLE|RES|UPDATE] updating role")
	diagnostics = resourceRoleCreate(ctx, d, m)
	log.Println("[ROLE|RES|UPDATE] updated role")
	return
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[ROLE|RES|READ] reading role")
	client := m.(*client.ClientHolder)
	id := d.Id()
	role, ok, err := client.Role.Get(id)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "couldn't get role with id: %s", id))
		return
	}
	if !ok {
		diagnostics = diag.Errorf("couldn't find expected resource")
		return
	}
	log.Printf("[ROLE|RES|READ] got role: %#v", role)
	d.Set("name", role.Name)
	d.Set("description", role.Description)
	metadatatags := []interface{}{map[string]interface{}{
		"template": role.UnmarshalledSpec.Metadata.Tags.Template,
	}}
	d.Set("metadatatags", metadatatags)
	spec := []interface{}{map[string]interface{}{
		"known_device_only": role.UnmarshalledSpec.Spec.KnownDeviceOnly,
		"group":             role.UnmarshalledSpec.Spec.Group,
		"email":             role.UnmarshalledSpec.Spec.Email,
		"mdm_present":       role.UnmarshalledSpec.Spec.MDMPresent,
		"device_ownership":  role.UnmarshalledSpec.Spec.DeviceOwnership,
		"platform":          role.UnmarshalledSpec.Spec.Platform,
	}}

	d.Set("spec", spec)
	d.SetId(role.ID)
	log.Println("[ROLE|RES|READ] read role")
	return
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[ROLE|RES|DELETE] deleting role")

	client := m.(*client.ClientHolder)
	err := client.Role.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Println("[ROLE|RES|DELETE] deleted role")
	return
}
