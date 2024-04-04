package banyan

import (
	"context"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/scim"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSCIM() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSCIMCreate,
		ReadContext:   resourceSCIMRead,
		UpdateContext: resourceSCIMUpdate,
		DeleteContext: resourceSCIMDelete,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the access tier group in Banyan",
				ForceNew:    true,
			},
			"is_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Is scim enabled for an org",
			},
			"base_url": {
				Type:        schema.TypeString,
				Description: "base url of idp ",
				Optional:    true,
			},
			"token": {
				Type:        schema.TypeString,
				Description: "token is to communicate with idp",
				Sensitive:   true,
				Optional:    true,
				ForceNew:    true,
			},
			"token_info": {
				Type:     schema.TypeSet,
				MaxItems: 2,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"uuid": {
							Type:        schema.TypeString,
							Description: "uuid of token",
							Optional:    true,
						},
						"created_at": {
							Type:        schema.TypeInt,
							Description: "time of token creation",
							Optional:    true,
						},
					},
				},
			},
		},
	}
}

func resourceSCIMCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)

	id, err := uuid.GenerateUUID()
	if err != nil {
		return
	}

	isEnabled := d.Get("is_enabled").(bool)

	post := scim.SCIMProvisionRequest{
		IsEnabled: isEnabled,
	}

	err = c.SCIM.ProvisionSCIM(post)
	if err != nil {
		return diag.FromErr(err)
	}

	if !isEnabled {
		d.SetId(id)
		return
	}

	key, err := c.SCIM.Create()
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("token", key.Data.Token)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("is_enabled", isEnabled)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("base_url", key.Data.BaseURL)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(id)

	return
}

func resourceSCIMUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	post := scim.SCIMProvisionRequest{
		IsEnabled: d.Get("is_enabled").(bool),
	}

	err := c.SCIM.Update(post, expandTokenInfo(d))
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceSCIMRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	key, err := c.SCIM.Get()
	if err != nil {
		handleNotFoundError(d, err)
		return
	}

	d.SetId(d.Get("id").(string))

	err = d.Set("is_enabled", d.Get("is_enabled").(bool))
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("base_url", key.BaseURL)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("token_info", flattenTokenInfo(key.Tokens))
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceSCIMDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.SCIM.Delete(expandTokenInfo(d))
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}

	d.SetId("")

	return
}

func flattenTokenInfo(tokenInfos []scim.TokenInfo) (flattened []interface{}) {
	if len(tokenInfos) == 0 {
		return
	}

	for _, tokenInfo := range tokenInfos {
		tl := make(map[string]interface{})
		if tokenInfo.UUID != "" {
			tl["uuid"] = tokenInfo.UUID
		}
		tl["created_at"] = tokenInfo.CreatedAt

		if len(tl) != 0 {
			flattened = append(flattened, tl)
		}
	}
	return
}

func expandTokenInfo(d *schema.ResourceData) (tokeninfos []scim.TokenInfo) {
	v, ok := d.GetOk("token_info")
	if !ok {
		return nil
	}
	tokens := v.(*schema.Set).List()
	for _, t := range tokens {

		uuid := t.(map[string]interface{})["uuid"].(string)
		createdAt := t.(map[string]interface{})["created_at"].(int)

		token := scim.TokenInfo{
			UUID:      uuid,
			CreatedAt: int64(createdAt),
		}

		tokeninfos = append(tokeninfos, token)
	}

	return
}
