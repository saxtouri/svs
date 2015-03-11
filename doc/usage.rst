Usage
#####

The InAcademia service uses the `OpenID Connect standard`_ to provide validation of an end-users affiliation with an
academic institution. In this protocol the InAcademia service acts as an `OpenID Connect provider` (OP), and to validate
an affiliation your service acts as a `Relying party` (RP).

In :ref:`transaction_flow` the protocol flow and the messages exchanged in one transaction are described. All supported
operations are described more in-depth in :ref:`supported_operations`.

Terminology and legend
======================

In addition to the terminology defined by `OpenID Connect standard`_, here follows some clarifications and additional
terms used in this document.

Relying Party (RP)
    Part of your service acting as a client of the InAcademia service using the OpenID Connect protocol.

OpenID Provider (OP)
    The InAcademia service.

Institution
    The academic institution the end-user is affiliated with.

Transaction
    One validation of affiliation at the InAcademia service. A transaction starts when the InAcademia service
    receives a valid OpenID Connect authentication request, and ends when the response of the
    validation is returned via the redirect URI.


.. list-table:: Legend
    :widths: 20 80

    * - Formatting
      - Description

    * - ``text``
      - literal values

    * - <text>
      - parameter substitution


.. _transaction_flow:

Transaction: validate affiliation
=================================

To validate an end-users affiliation with an institution you must be registered with the InAcademia service and have a
valid client id at the OP, see :ref:`client_registration`.


Start of transaction: Authentication Request
--------------------------------------------

A transaction is initiated when an `Authentication request` is received at the OP.
The authentication request is sent by redirecting the end-user to::

    <inacademia_base>/authorization?nonce=<nonce>&state=<state>&redirect_uri=<redirect_uri>&response_type=id_token&client_id=<client_id>&scope=<scope>


All parameters are described in :ref:`authentication_request`. Documentation of the authentication request can be found
in the section `Authentication using the Implicit Flow`_.

*Note: Because of the redirect, the request is made by a client (typically a web-browser), and the response is
delivered in the fragment identifier of the given redirect URI (see below).*


End of transacation: Redirect URI
---------------------------------

If the transaction succeeds, an `ID Token` (encoded as a JWT) will be returned in the fragment identifier part of the
redirect URI. This can then be parsed using some scripting language in the browser (e.g. Javascript) running in the
browser at the redirect URI.

Documentation of the response to a successful authentication can be found in the section
`Successful authentication request`_.


.. _client_registration:

Registration with the InAcademia service
========================================
**TODO**

.. _supported_operations:

Supported operations
====================

OpenID Provider Configuration
-----------------------------

To get the provider configuration of the InAcademia provider, the RP should make the following request::

    GET /.well-known/openid-configuration HTTP/1.1
    Host: <inacademia_base>

The response will be a JSON document containing for example the authorization endpoint (where to direct the
authorization request to validate the end-users affiliation).

Full documentation of the provider configuration exchange can be found in `OpenID Connect Discovery`_.


.. _affiliation_validation:

Affiliation validation
------------------------

.. _authentication_request:

Authentication request
^^^^^^^^^^^^^^^^^^^^^^

The authentication should be directed to::

    <inacademia_base>/authorization

The following parameters are allowed in the authentication request (any others will just be ignored):

.. list-table:: Authentication request parameters
    :widths: 10 80 10
    :header-rows: 1

    * - Parameter name
      - Value/description
      - State

    * - response_type
      - ``id_token``
      - Required

    * - client_id
      - <client_id>
      - Required

    * - scope
      - See scope mapping table in :ref:`requested_scope_rules`
      - Required

    * - redirect_uri
      - URL to send response to, must be previously registered with the InAcademia service
      - Required

    * - nonce
      - opaque string to associate
      - Required

    * - state
      - opaque string to maintain state between your RP and the InAcademia OP
      - Recommended

    * - claims
      - Any additional claims that should be returned in the id token.
      - Optional


.. _requested_scope_rules:

Type of affiliation
^^^^^^^^^^^^^^^^^^^

The type of affiliation validation for the transaction is specified in the `scope` of the authentication request.
There are two categories of scopes allowed:

    #) **Affiliation:** what type of affiliation should be validated?
    #) **Identifier:** what type of identifier is requested (persistent, to be able to identify returning users, or
       transient, unique for each validation transaction)?

A valid scope string must fulfill the following:
    #) Exactly one value from the affiliation category of scopes must be specified.
    #) At most one value from the identifier category may be specified. If no value from the identifier category is
       specified, `transient` (see below table for description) is assumed.

Hence, the affiliation scope is required while both identifier and other scopes are optional. Any ambiguous scope
strings will be immediately rejected by the InAcademia service.

The table below contains all values, grouped by category, allowed in the scope string:

.. list-table:: Allowed scope values
    :widths: 10 10 80
    :header-rows: 1
    :stub-columns: 1

    * -
      - Scope
      - Description

    * - Affiliation
      - affiliated
      - Is the end-user affiliated to the institution?

    * -
      - student
      - Is the end-user a student at the institution?

    * -
      - faculty+staff
      - Is the end-user a teacher/researcher (faculty) or a worker (other than teacher/researcher, staff) at the institution?

    * -
      - alum
      - Is the end-user an alumni at the institution?

    * - Identifier
      - persistent
      - Persistent identifier, unique for this end-user.

    * -
      - transient
      - Transient identifier, which is unique for each transaction.

.. _additional_claims:

Additional claims
^^^^^^^^^^^^^^^^^

To request additional claims about the end user, the ``claims`` parameter can be specified in the authentication
request, see `Claims Parameter in Authentication request`_. Only "``id_token``" is supported as a top-level member and
requests for a claim with a particular value are not supported.

The additional claims that can be requested can be seen in the following table:

.. list-table:: Allowed claims values
    :header-rows: 1
    :stub-columns: 1

    * - Claim
      - Description

    * - country
      - The country of the users home institution.

    * - domain
      - The domain name of the users home institution.


Transaction success
^^^^^^^^^^^^^^^^^^^

If the transaction succeeds an id token and the state (if included in the initial authentication request) will be
returned in the fragment identifier part of the redirect URI (see `Successful authentication request`_). The id token
is a JSON Web Token, containing a JSON document with all returned claims, see the table below. The id token should be
validated, see `ID Token Validation`_.

.. list-table:: ID Token claims
    :widths: 20 80
    :header-rows: 1

    * - Claim
      - Description

    * - aud
      - list which must contain your client id, otherwise the id token must be rejected

    * - auth_time
      - when the end-user authenticated at its institution

    * - exp
      - the id tokens expiration date, approximately 30 minutes after the end-user authenticated at its institution

    * - iat
      - when the id token was issued

    * - iss
      - issuer identifier of the InAcademia service, must exactly match <inacademia_base>

    * - nonce
      - if your initial authentication request contained a nonce, this value should be matched exactly with that

    * - sub
      - identifier of the transaction/end-user. If a transient identifier was requested this value will be unique per
        transaction. If a persistent identifier was requested this value will be unique per end-user.


The id token may also contain additional claims. The claims in the table :ref:`tbl:additional_claims` below will be
included if:

    #) you are allowed to obtain them
    #) they were requested in the initial authentication request (see :ref:`additional_claims`)
    #) the institution provides them to the InAcademia service


.. _`tbl:additional_claims`:
.. list-table:: Additional (optional) id token claims
    :widths: 20 80
    :header-rows: 1

    * - Claim
      - Description

    * - country
      - country code (ISO_3166-1_alpha-3) of the institution

    * - domain
      - domain name of the institution

Transaction fail
^^^^^^^^^^^^^^^^

A transaction will only be started if:
    #) the RP is registered with the InAcademia service and has a valid client id
    #) the `Redirect URI`, specified in the authentication request, is among the URL's given when registering with the
       InAcademia service
    #) the scope specified in the authentication request is valid
    #) the response type is correct (only ``id_token`` is supported)

If 1. or 2. is not satisfied, no response will be sent to the RP, instead an error will be displayed to the end user.
If 3. or 4. is not satisfied, an error response will be sent (see :ref:`possible_errors` for error codes).
The error response will be encoded in the fragment part of the redirect URI::

    <redirect_uri>#error=<error_code>&error_description=<error_description>

where the ``error_description`` is optional and therefore might be missing.

The transaction will fail if:
    #) the end-user wants to validate its affiliation with an for the InAcademia service unknown institution or an
       institution not part of `eduGAIN`
    #) the end-user was not authenticated at the selected institution
    #) the institution did not provide enough information to the InAcademia service to validate the affiliation
    #) the end-user did not give consent to release the necessary information

If the transaction fails an error code and possibly an error description will be returned in the fragment part of the
redirect URI (in the same way as described above).


.. _possible_errors:

Possible errors
^^^^^^^^^^^^^^^

.. list-table:: Error codes
    :widths: 20 80
    :header-rows: 1

    * - Error code
      - Reasons

    * - ``access_denied``
      - end-user unauthorized, unknown or non-eduGAIN institution, the affiliation could not be validated

    * - ``invalid_scope``
      - invalid scope specified in the authentication request (see :ref:`requested_scope_rules`)

    * - ``unsupported_response_type``
      - incorrect response type in the authentication request (must be ``id_token``)


.. _OpenID Connect standard: http://openid.net/specs/openid-connect-core-1_0.html
.. _OpenID Connect Discovery: http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
.. _Authentication using the Implicit Flow: http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
.. _Successful authentication request: http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
.. _OpenID Provider Metadata: http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
.. _ID Token Validation: http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
.. _Claims Parameter in Authentication request: http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter