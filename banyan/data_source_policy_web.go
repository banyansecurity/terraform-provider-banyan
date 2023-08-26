package banyan

import (
	"context"

	"github.com/pkg/errors"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourcePolicyWebSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the policy",
		},
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the policy in Banyan",
		},
		"description": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Description of the policy",
		},
		"access": {
			Type:        schema.TypeList,
			Computed:    true,
			Description: "Access describes the access rights for a set of roles",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"roles": {
						Type:        schema.TypeSet,
						Description: "Role names to include ",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
						Computed: true,
					},
					"trust_level": {
						Type:        schema.TypeString,
						Description: "The trust level of the end user device, must be one of: \"High\", \"Medium\", \"Low\", or \"\"",
						Computed:    true,
					},
					"l7_access": {
						Type:        schema.TypeList,
						Description: "Indicates whether the end user device is allowed to use L7",
						Computed:    true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"resources": {
									Type: schema.TypeSet,
									Description: `
										Resources are a list of application level resources.
										Each resource can have wildcard prefix or suffix, or both.
										A resource can be prefixed with "!", meaning DENY.
										Any DENY rule overrides any other rule that would allow the access.`,
									Computed: true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"actions": {
									Type:        schema.TypeSet,
									Description: "Actions are a list of application-level actions: \"CREATE\", \"READ\", \"UPDATE\", \"DELETE\", \"*\"",
									Computed:    true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return
}

func dataSourcePolicyWeb() *schema.Resource {
	return &schema.Resource{
		Description: "Obtains information describing the web policy from banyan",
		ReadContext: dataSourcePolicyWebRead,
		Schema:      dataSourcePolicyWebSchema(),
	}
}

// /v1/security_policies
func dataSourcePolicyWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {

	client := m.(*client.Holder)
	webPolicy, err := client.Policy.GetName(d.Get("name").(string))

	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}

	if webPolicy.ID == "" {
		err = errors.New("Could not find role with name: " + d.Get("name").(string))
		return diag.FromErr(err)
	}

	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("name", webPolicy.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", webPolicy.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyWebAccess(webPolicy.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(webPolicy.ID)
	return
}
