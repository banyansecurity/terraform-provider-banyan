package role

type Spec struct {
	DeviceOwnership []string `json:"device_ownership"`
	Email           []string `json:"email"`
	Group           []string `json:"group"`
	KnownDeviceOnly bool     `json:"known_device_only"`
	MDMPresent      bool     `json:"mdm_present"`
	Platform        []string `json:"platform"`
}

type CreateRole struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Type       string   `json:"type"`
	Spec       Spec     `json:"spec"`
}

type Metadata struct {
	Description string `json:"description"`
	Name        string `json:"name"`
	Tags        Tags   `json:"tags"`
}

type Tags struct {
	Template string `json:"template"`
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
