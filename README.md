Terraform Provider for banyan
==================

Now in Beta. 

This is the Bayan Terraform Provider. This provider will allow you to interact with Banyan resources. 
Please see the `examples` and `docs` folders for the current documentation.

Installation Instructions
-------------------------

To build the provider run
`make install`

This will build the provider and install it locally on your machine.

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

Pull Requests
-------------------------------

All PRs should have an associated issue.