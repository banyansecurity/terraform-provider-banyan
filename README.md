Terraform Provider for banyan
==================

Now in Beta. 

This is the Bayan Terraform Provider. This provider will allow you to interact with Banyan resources. 
Please see the `examples` and `docs` folders for the current documentation.

Update Notes
-----------

As the provider approaches a 1.0 release, some resources add attributes have been simplified and abstracted away.

Most notably, the service resources names have been shortened and following parameters have been depreciated. 
 *  `cluster` 

Maintainers
-----------

This provider plugin is maintained by:

* Banyan

Requirements
------------

- [Terraform](https://www.terraform.io/downloads.html) 0.13+

Docs Pages

Developing the provider
---------------------------

To compile the provider, run `make install`.
This will build the provider and put the provider binary into your local terraform provider directory

Pull Requests
-------------------------------

All PRs should have an associated issue.