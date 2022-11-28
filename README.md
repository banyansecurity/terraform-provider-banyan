Banyan Provider
==================

The Banyan Terraform Provider contains resources used to automate zero trust network access utilizing the Banyan API.

For more information visit the [Banyan website](https://www.banyansecurity.io/) or the [Banyan documentation](https://docs.banyansecurity.io/docs/)

Update Notes
-----------

As the provider approaches a 1.0 release, some resources add attributes have been simplified and abstracted away. This refactor includes new resources as well as resource schemas which resemble the 1.0 release as much as possible.

After feedback and usage of the provider it was determined to consolidate and simplify naming and parameters for some resources.

Most notable are the service and policy resources.
* The `banyan_service` resources now have a `policy` attribute which replaces the `banyan_policy_attachment` resource
* The `banyan_service` resources no longer require a `cluster` attribute. This value will be determined automatically by the `access_tier` or `connector` attribute
* The cluster parameter is no longer needed for any resources and should only be set for backwards compatibility (i.e. upgrading pre 0.9.0 terraform code)
* The `banyan_service` resources no longer requires a `cluster` attribute. This value will be determined by the `access_tier` or `connector` attribut
* `banyan_policy_attachment` has been depreciated. This now exists as the `policy` attribute for the service resourcee
*  The `banyan_service_infra` resources have been depreciated and renamed. It is safe to modify existing terraform code to utilize the new shorted name, and to add the id of the policy to attach to the `policy` attribute. see the upgraded resources examples. This would effectively recreate the services with the new format and remove the services and policy attachments created in the old format.
* `banyan_policy_attachment` has been depreciated. This now exists as the `policy` attribute for the service resource

The corresponding command center release brings with it new changes to the access tier which are reflected in this release of the terraform provider

Be sure to check out the new accesstier2 modules for your cloud provider on the [Terraform Registry](https://registry.terraform.io/providers/banyansecurity/banyan/0.9.2)

View this release in the [Terraform Registry](https://registry.terraform.io/providers/banyansecurity/banyan/0.9.2)

## What's Changed
* major refactor of the provider and client providing much cleaner and simpler code
* added support for service tunnel
* accesstier2 support
* connector improvements
* documentation and examples improvements
* better resource lifecycle management
* acceptance testing against the Banyan API
* various additional resources and attributes to align with the latest Banyan features
* New resource `bayan_policy_tunnel` for use with `banyan_service_tunnel`
* Hotfixes and docs updates for 0.9.1



Maintainers
-----------

This provider plugin is maintained by Banyan

Requirements
------------

- [Terraform](https://www.terraform.io/downloads.html) 0.13+


Documentation
-------------

[This provider on the Terraform Registry](https://registry.terraform.io/providers/banyansecurity/banyan/latest/docs)

Developing the provider
---------------------------

To compile the provider, run `make install`.
This will build the provider and put the provider binary into your local terraform provider directory

Pull Requests
-------------------------------

All PRs should have an associated issue.
