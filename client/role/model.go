package role

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const(
	DefaultAPIVersion = "v1"
)

// Info represents the specification of a role populated by json.Unmarshal.
type Info struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Type       string `json:"type"` //attribute, name (-based)
	Metadata   `json:"metadata"`
	Spec       `json:"spec"`
}

// Metadata Parameters represents the parameters stanza of a role.Info.
type Metadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Tags        Tags   `json:"tags"`
}

// Tags represents the metadata tags
type Tags struct {
	Template string `json:"template"`
}

// Spec represents the attributes stanza of a role.Info.
type Spec struct {
	ContainerFQDN []string    `json:"container_fqdn"`
	Image         []string    `json:"image"`
	RepoTag       RepoTagList `json:"repo_tag"`
	LabelSelector []LabSel    `json:"label_selector"`
	ServiceAccts  []string    `json:"service_account"`

	// The remaining fields relate to users and devices
	UserGroup       []string `json:"group"`
	Email           []string `json:"email"`
	DeviceOwnership []string `json:"device_ownership"`
	Platform        []string `json:"platform"`
	KnownDeviceOnly bool     `json:"known_device_only"`
	MDMPresent      bool     `json:"mdm_present"`

	SerialNumbers []string `json:"serial_numbers"`
}

// RepoTagList is a list of repo:tag strings within a role.Spec.
type RepoTagList []string

// LabSel represents a label map within a role.Spec.
type LabSel map[string]string

type CreateRole struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Type       string   `json:"type"`
	Spec       Spec     `json:"spec"`
}

type GetRole struct {
	CreatedAt        int    `json:"CreatedAt"`
	CreatedBy        string `json:"CreatedBy"`
	DeletedAt        int    `json:"DeletedAt"`
	DeletedBy        string `json:"DeletedBy"`
	Description      string `json:"Description"`
	LastUpdatedAt    int    `json:"LastUpdatedAt"`
	LastUpdatedBy    string `json:"LastUpdatedBy"`
	ID               string `json:"RoleID"`
	Name             string `json:"RoleName"`
	Spec             string `json:"RoleSpec"`
	Version          int    `json:"RoleVersion"`
	IsEnabledString  string `json:"Enabled"`
	IsEnabled        bool
	UnmarshalledSpec CreateRole
}

type ListSecurityRoleResponse struct {
	Roles []V2SecurityRoleInfo `json:"roles"`
	Count int64                `json:"count"`
}

type V2SecurityRoleInfo struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	OrgID              string `json:"org_id"`
	Spec               string `json:"spec"`
	CreatedBy          string `json:"created_by"`
	CreatedAt          int64  `json:"created_at"`
	LastUpdatedBy      string `json:"last_updated_by"`
	LastUpdatedAt      int64  `json:"last_updated_at"`
	Description        string `json:"description"`
	Type               string `json:"type"`
	Version            int64  `json:"version"`
	DeletedBy          string `json:"deleted_by"`
	DeletedAt          int64  `json:"deleted_at"`
	Enabled            string `json:"enabled"`
	DeviceCount        uint64 `json:"device_count"`
	PolicyCount        uint64 `json:"policy_count"`
	ThreatProfileCount uint64 `json:"threat_profile_count"`
	Active             bool   `json:"active"`
}

type V2Resp struct {
	RequestID        string             `json:"request_id"`
	ErrorCode        int                `json:"error_code"`
	ErrorDescription string             `json:"error_description"`
	Data             V2SecurityRoleInfo `json:"data"`
}

type V2ListResp struct {
	RequestID        string                   `json:"request_id"`
	ErrorCode        int                      `json:"error_code"`
	ErrorDescription string                   `json:"error_description"`
	Data             ListSecurityRoleResponse `json:"data"`
}

func SetRoleStateFromSpec(d *schema.ResourceData, spec CreateRole) (err error) {
	err = d.Set("container_fqdn", spec.Spec.ContainerFQDN)
	if err != nil {
		return err
	}
	err = d.Set("image", spec.Spec.Image)
	if err != nil {
		return err
	}
	err = d.Set("repo_tag", spec.Spec.RepoTag)
	if err != nil {
		return err
	}
	err = d.Set("user_group", spec.Spec.UserGroup)
	if err != nil {
		return err
	}
	err = d.Set("email", spec.Spec.Email)
	if err != nil {
		return err
	}
	err = d.Set("device_ownership", spec.Spec.DeviceOwnership)
	if err != nil {
		return err
	}
	err = d.Set("platform", spec.Spec.Platform)
	if err != nil {
		return err
	}
	err = d.Set("known_device_only", spec.Spec.KnownDeviceOnly)
	if err != nil {
		return err
	}
	err = d.Set("mdm_present", spec.Spec.MDMPresent)
	if err != nil {
		return err
	}
	err = d.Set("serial_numbers", spec.Spec.SerialNumbers)
	if err != nil {
		return err
	}
	return
}
