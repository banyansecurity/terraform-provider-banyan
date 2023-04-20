Banyan Provider
==================

The Banyan Terraform Provider contains resources used to automate zero trust network access utilizing the Banyan API.

For more information visit the [Banyan website](https://www.banyansecurity.io/) or the [Banyan documentation](https://docs.banyansecurity.io/docs/)

## Important Note about API key scope
`ServiceAuthor` and `PolicyAuthor` limit the API key permissions to `services` and `policies` respectively. These narrowed API key scopes can be used to delegate service and policy management to teams or CI systems.

An `Admin` scope API key will have permission to create, modify, or destroy any resource which is available in terraform. An `Admin` scope
API key is *required* in order to manage an access tier, connector, or service tunnel.

`access_tier` and `connector` API key scopes are required by the *launch configuration* of access tiers and connectors. Terraform is able to provision `access_tier` and `connector` API keys which are used by access tier and connector instances. The  [access tier](https://registry.terraform.io/modules/banyansecurity/banyan-accesstier2) and [connector](https://registry.terraformio/modules/banyansecurity/banyan-connector) terraform modules use these API key scopes to launch access tier and connector instances.

## Important Note about terraform Import
You must use "terraform import" with care. If you import a resource that uses attributes not supported in the Banyan Terrafrom provider as yet, those attributes will get overwritten and you will encounter unexpected behavior.

Update Notes
-----------

* `policy` is no longer a required attribute of any service type.
* all services containing `banyan_service_infra_` in the name were depreciated in v1.0.0. They have been removed from the provider in this release and were replaces by the current service resources.
* `banyan_policy_attachment` was deprecated in v1.0.0 and has been removed from the provider in this release. The new service resources support inline policy attachment.
* `banyan_service_k8s` now has `http_connect` always enabled and this parameter is no longer configurable, matching the UI.
* various bug fixes and improvements
* updated documentation and examples



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
