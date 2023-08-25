package banyan

import (
	"context"

	"github.com/pkg/errors"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourcePolicyInfraSchema() (s map[string]*schema.Schema) {
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
				},
			},
		},
	}
	return
}

func dataSourcePolicyInfra() *schema.Resource {
	return &schema.Resource{
		Description: "Obtains information describing the infra policy from banyan",
		ReadContext: dataSourcePolicyInfraRead,
		Schema:      dataSourcePolicyInfraSchema(),
	}
}

// /v1/security_policies
func dataSourcePolicyInfraRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {

	client := m.(*client.Holder)
	infraPolicy, err := client.Policy.GetName(d.Get("name").(string))

	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}

	if infraPolicy.ID == "" {
		err = errors.New("Could not find role with name: " + d.Get("name").(string))
		return diag.FromErr(err)
	}

	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("name", infraPolicy.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", infraPolicy.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyInfraAccess(infraPolicy.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(infraPolicy.ID)
	return
}
