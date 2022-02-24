package role

import "sync"

// Info represents the specification of a role populated by json.Unmarshal.
type Info struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Type       string `json:"type"` //attribute, name (-based)
	Metadata   `json:"metadata"`
	Spec       `json:"spec"`
}

// Parameters represents the parameters stanza of a role.Info.
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
}

// RepoTagList is a list of repo:tag strings within a role.Spec.
type RepoTagList []string

// Records keeps track of role definitions and the record of
// which containers can take on which roles.
type Records struct {
	sync.RWMutex
	// dirty flag indicates if records have changed since last dumped
	dirty bool
	// serviceAccounter, if not nil, looks up service account info for containers
	serviceAccounter ServiceAccounter

	// roleInfoFromRoleName: key=role name, val=role infoID
	roleInfoFromRoleName map[string]infoID
	// rolesFromContainerID: key=containerID val=list of role names
	rolesFromContainerID map[string][]string
	// containerIDsFromRoleName: key=role name, val=list of containerIDs
	containerIDsFromRoleName map[string][]string
	// rolesFromServiceAccount: key=service account, val: map(key=role, val=true)
	rolesFromServiceAccount map[string]map[string]bool
	// serviceAccountFromRoles: key=role, val: map(key=service account, val=true)
	serviceAccountsFromRole map[string]map[string]bool
}

// ServiceAccounter is any type that implements the ServiceAccount() method.
type ServiceAccounter interface {
	ServiceAccount(containerID string) string
}

type infoID struct {
	Info
	ID      string
	Version int
}

// NewRecords creates a new Records.
func NewRecords() (r *Records) {
	r = &Records{
		rolesFromContainerID:     make(map[string][]string),
		containerIDsFromRoleName: make(map[string][]string),
		roleInfoFromRoleName:     make(map[string]infoID),
		rolesFromServiceAccount:  make(map[string]map[string]bool),
		serviceAccountsFromRole:  make(map[string]map[string]bool),
	}
	return r
}

// Diff is returned by Records.CheckNonExistentRoles() and is used to report a new set of roles (could be empty) for a container.
type Diff struct {
	// ContainerID identifies a container
	ContainerID string
	// Roles are all the roles the corresponding container can take on
	Roles []string
	// Versions are the corresponding role versions : len(Versions) == len(Roles)
	Versions []int
}

type UserClaims struct {
	Name   string
	Email  string
	Phone  string
	Groups []string
}

type DeviceClaims struct {
	DeviceID        string
	SerialNumber    string
	DeviceOwnership string
	Platform        string
	MDMPresent      bool
	IsStagedInstall bool
	Unregistered    bool
}

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
