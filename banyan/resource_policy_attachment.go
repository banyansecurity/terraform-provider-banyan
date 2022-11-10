package banyan

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePolicyAttachment() *schema.Resource {
	return &schema.Resource{
		Description:        "(Depreciated) The policy attachment resource attaches a policy to a service. This functionality has been moved to the \"policy\" parameter of the respective service resource",
		CreateContext:      resourcePolicyAttachmentCreate,
		ReadContext:        resourcePolicyAttachmentRead,
		UpdateContext:      resourcePolicyAttachmentUpdate,
		DeleteContext:      resourcePolicyAttachmentDelete,
		DeprecationMessage: "This resource is depreciated and will be removed from the provider in the 1.0 release. Please utilize the \"policy\" parameter of the respective service resource",
		Schema: map[string]*schema.Schema{
			"policy_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the policy",
				ForceNew:    true,
			},
			"attached_to_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the resource the policy will be attached to",
				ForceNew:    true,
			},
			"attached_to_type": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Type which the policy is attached to (i.e. service / saasapp)",
				ValidateFunc: validation.StringInSlice([]string{"service", "saasapp"}, false),
				ForceNew:     true,
			},
			"is_enforcing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Sets whether the policy is enforcing or not",
				Default:     true,
			},
		},
	}
}

// build the policy attachment id
func buildPolicyAttachmentID(attachment policyattachment.GetBody) (id string) {
	return fmt.Sprintf("%s..%s..%s", attachment.PolicyID, attachment.AttachedToType, attachment.AttachedToID)
}

func getInfoFromPolicyAttachmentID(terraformPolicyAttachmentID string) (policyID, attachedToType, attachedToID string) {
	policyIDParts := strings.Split(terraformPolicyAttachmentID, "..")
	policyID = policyIDParts[0]
	attachedToType = policyIDParts[1]
	attachedToID = policyIDParts[2]
	return
}

func resourcePolicyAttachmentCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	policyID := d.Get("policy_id").(string)
	attachedToID := d.Get("attached_to_id").(string)
	attachedToType := d.Get("attached_to_type").(string)
	isEnforcing := d.Get("is_enforcing").(bool)
	Enabled := "FALSE"
	if isEnforcing {
		Enabled = "TRUE"
	}
	creatPolicyAttachment := policyattachment.CreateBody{
		AttachedToID:   attachedToID,
		AttachedToType: attachedToType,
		IsEnabled:      isEnforcing,
		Enabled:        Enabled,
	}
	createdPolicyAttachment, err := c.PolicyAttachment.Create(policyID, creatPolicyAttachment)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId(buildPolicyAttachmentID(createdPolicyAttachment))
	return
}

func resourcePolicyAttachmentRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	_, attachedToType, attachedToID := getInfoFromPolicyAttachmentID(id)
	attachment, err := c.PolicyAttachment.Get(attachedToID, attachedToType)
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("policy_id", attachment.PolicyID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("attached_to_id", attachment.AttachedToID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("attached_to_type", attachment.AttachedToType)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("is_enforcing", attachment.IsEnabled)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourcePolicyAttachmentUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourcePolicyAttachmentCreate(ctx, d, m)
	return
}

func resourcePolicyAttachmentDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.PolicyAttachment.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId("")
	return
}
