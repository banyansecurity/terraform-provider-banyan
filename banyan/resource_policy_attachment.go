package banyan

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

// The policy attachment resource. For more information on Banyan policy attachments, see the documentation:
func resourcePolicyAttachment() *schema.Resource {
	return &schema.Resource{
		Description:   "A Banyan policy attachment. Attaches a policy.",
		CreateContext: resourcePolicyAttachmentCreate,
		ReadContext:   resourcePolicyAttachmentRead,
		UpdateContext: resourcePolicyAttachmentUpdate,
		DeleteContext: resourcePolicyAttachmentDelete,
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
				ValidateFunc: validateAttachedToType(),
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

func validateAttachedToType() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v != "service" && v != "saasapp" {
			// this error message might need to be cleaned up to handle the empty trustlevel
			errs = append(errs, fmt.Errorf("%q must be one of the following %q, got: %q", key, []string{"service", "saasapp"}, v))
		}
		return
	}
}

func getPolicyAttachmentID(attachment policyattachment.GetBody) (id string) {
	id = fmt.Sprintf("%s..%s..%s", attachment.PolicyID, attachment.AttachedToType, attachment.AttachedToID)
	return
}

func getInfoFromPolicyAttachmentID(terraformPolicyAttachmentID string) (policyID, attachedToType, attachedToID string) {
	policyIDParts := strings.Split(terraformPolicyAttachmentID, "..")
	policyID = policyIDParts[0]
	attachedToType = policyIDParts[1]
	attachedToID = policyIDParts[2]
	return
}

func resourcePolicyAttachmentCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICYATTACHMENT|RES|CREATE] creating policyAttachment")
	client := m.(*client.Holder)
	policyID, ok := d.Get("policy_id").(string)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert policy_id")
		return
	}
	attachedToID, ok := d.Get("attached_to_id").(string)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert attached_to_id")

		return
	}
	attachedToType, ok := d.Get("attached_to_type").(string)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert attached_to_type")
		return
	}
	isEnforcing, ok := d.Get("is_enforcing").(bool)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert is_enforcing")

		return
	}
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

	log.Printf("[POLICYATTACHMENT|RES|CREATE] to be created: %#v\n", creatPolicyAttachment)
	createdPolicyAttachment, err := client.PolicyAttachment.Create(policyID, creatPolicyAttachment)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Printf("[POLICYATTACHMENT|RES|CREATE] createdpolicyAttachment %#v\n", createdPolicyAttachment)
	d.SetId(getPolicyAttachmentID(createdPolicyAttachment))
	return
}

func resourcePolicyAttachmentUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICYATTACHMENT|RES|UPDATE] updating policyAttachment")
	diagnostics = resourcePolicyAttachmentCreate(ctx, d, m)
	log.Println("[POLICYATTACHMENT|RES|UPDATE] updated policyAttachment")
	return
}

func resourcePolicyAttachmentRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICYATTACHMENT|RES|READ] reading policyAttachment")
	client := m.(*client.Holder)
	id := d.Id()
	_, attachedToType, attachedToID := getInfoFromPolicyAttachmentID(id)
	attachment, ok, err := client.PolicyAttachment.Get(attachedToID, attachedToType)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get policyAttachment with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("policy attachment %q", d.Id()))
	}
	log.Printf("[POLICYATTACHMENT|RES|READ] got policyAttachment: %#v", attachment)
	d.Set("policy_id", attachment.PolicyID)
	d.Set("attached_to_id", attachment.AttachedToID)
	d.Set("attached_to_type", attachment.AttachedToType)
	d.Set("is_enforcing", attachment.IsEnabled)
	log.Println("[POLICYATTACHMENT|RES|READ] read policyAttachment")
	return
}

func resourcePolicyAttachmentDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICYATTACHMENT|RES|DELETE] deleting policyAttachment")

	client := m.(*client.Holder)
	policyID, attachedToType, attachedToID := getInfoFromPolicyAttachmentID(d.Id())

	err := client.PolicyAttachment.Delete(policyID, policyattachment.DetachBody{
		AttachedToID:   attachedToID,
		AttachedToType: attachedToType,
	})
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Println("[POLICYATTACHMENT|RES|DELETE] deleted policyAttachment")
	return
}
