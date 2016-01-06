Code samples for connecting clients to the InAcademia service
#############################################################

As described in the :doc:`usage <../usage>` of the InAcademia service, there are two steps in a
transaction: 1) making an authentication request, and 2) receiving the response. A third step should
be performed beforehand, provider configuration discovery. All these steps are described in detail
for a number of libraries/frameworks below.

Note: the following code samples are not secure enough to be used in a live production environment,
they are only intended to document the basic steps required to complete a transaction with the
InAcademia service. Additional measures should be implemented to increase the security.


Python: pyoidc_
===============

Java: `Nimbus OAuth 2.0 SDK`_
=============================


Apache: `mod_auth_openidc`_Ex
===========================

Javascript
==========


.. _pyoidc: https://github.com/rohe/pyoidc
.. _Nimbus OAuth 2.0 SDK: http://connect2id.com/products/nimbus-oauth-openid-connect-sdk
.. _mod_auth_openidc: https://github.com/pingidentity/mod_auth_openidc
