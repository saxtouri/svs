OpenID Connect Provider implementation details
##############################################

Choice of SP
============

The choice of which SP should handle communication with the IdP is based on the requested scope: if ``persistent`` is
included in the requested scope the SP with that attribute requirement is selected, otherwise the transient SP is
chosen.


Subject identifier in ID Token
==============================

The subject identifier in the id token is based on the RP's client id, the end-users name id (either transient or
persitent as returned by the IdP). It is generated as follows::

    sha512(<client_id> + <user_id> + <idp_entity_id>)


User consent
============

Before releasing any information to the requesting RP, a consent page is displayed to the user when the SAML
authentication response is received. Only if the user consents to releasing all of the necessary information will the
id token be created and sent to the RP via the redirect URI.


.. _general_error_handling:

General error handling
======================

The global CherryPy configuration is updated to contain a special error handler (under the key
`request.error_response`), which will set the response status to 418 (I'm a teapot) for the automatic error response
sent by CherryPy for any uncatched application exception.


Error codes
===========

.. image:: /images/inacademia_flow.png

.. list-table:: Error mappings
    :widths: 30 60 10
    :header-rows: 1
    :stub-columns: 1

    * -
      - Error
      - Response

    * - \(1\) Users starts validation at RP
      - *out of scope*
      - --

    * - \(2\) RP makes authentication request
      - RP is not registered at InAcademia
      - ``unauthorized_client``

    * -
      - RP registered, but invalid client id
      - ``unauthorized_client``

    * -
      - RP registered, but redirect URI not valid
      - ``invalid_request``

    * -
      - Invalid scope requested
      - ``invalid_scope``

    * -
      - Response type not ``id_token``
      - ``unsupported_response_type``

    * - \(3\) InAcademia redirects user to discovery service
      - *out of scope*
      - --

    * - \(4\) End-user selects and IdP
      - *out of scope*
      - --

    * - \(5\) Response from discovery service
      - Invalid RelayState
      - *RP is unknown, notify end-user and log it*

    * -
      - Selected IdP is not a member of eduGAIN
      - ``access_denied``


    * - \(6\) InAcademia creates SAML authentication request
      - Software and/or config error
      - HTTP 418 (see `general_error_handling`_)

    * - \(7\) User authenticates at IdP
      - *out of scope*
      - --

    * - \(8\) IdP replies to InAcademia
      - User not authenticated
      - ``access_denied``

    * -
      - Incorrect SAML response
      - ``access_denied``

    * -
      - Missing attributes in reply
      - ``access_denied``

    * -
      - Incorrect values of attribute (only affiliation)
      - ``access_denied``


    * - \(9\) InAcademia asks user for consent
      - User does not give consent
      - ``access_denied``

    * - General errors
      - Unsolicited response at any endpoint
      - HTTP 404

    * -
      - Incorrect RelayState
      - ``access_denied``


Signal handling
===============

Since the InAcademia is provided in a Docker image the SIGTERM signal must be handled to allow the command
``docker stop`` to request a clean shutdown of the InAcademia process.
