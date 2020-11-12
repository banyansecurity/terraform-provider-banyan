Terraform Provider for banyan
==================

Still in alpha

Maintainers
-----------

This provider plugin is maintained by:

* Banyan

Requirements
------------

- [Terraform](https://www.terraform.io/downloads.html) 0.13+

Developing the provider
---------------------------

If you wish to work on the provider, you'll first need [Go](http://www.golang.org)
installed on your machine (version 1.15.0+ is *required*). currently requires gvm to manage go versions

To compile the provider, run `make install`.
This will build the provider and put the provider binary into your local terraform provider directory
