SAML Service Provider implementation details
############################################

Persistent vs transient name id
===============================

Currently two different SP's are used in the InAcademia service to provide different attribute requirements.

Transient SP attribute requirements
-----------------------------------

    * Transient SAML nameID
    * *required:* eduPersonAffiliation (urn:oid:1.3.6.1.4.1.5923.1.1.1.1)
    * *optional:* schacHomeOrganization (urn:oid:1.3.6.1.4.1.25178.1.2.9)


Persistent SP attribute requirements
------------------------------------

To accommodate as many IdP's as possible the InAcademia service requests multiple attributes (persistent nameID,
eduPersonTargetedId, eduPersonPrincipalName) related to user id. See :ref:`choose_name_id` as to how the final user id
is chosen.

    * Persistent SAML nameID
    * *required:* eduPersonAffiliation (urn:oid:1.3.6.1.4.1.5923.1.1.1.1)
    * *optional:* schacHomeOrganization (urn:oid:1.3.6.1.4.1.25178.1.2.9)
    * *optional:* eduPersonTargetedID (urn:oid:1.3.6.1.4.1.5923.1.1.1.10)
    * *optional:* eduPersonPrincipleName (urn:oid:1.3.6.1.4.1.5923.1.1.1.6)


SAML Relay State
================

The RelayState is used to encode the state necessary to handle any started transaction on any node (such that the
responses from the discovery server and the IdP can be routed to any node, not only the node where the transaction was
initiated).

The RelayState contains
 * client_id: OpenID Connect client id of the RP initiating the transaction
 * state: state sent by the RP in the authentication request
 * nonce: nonce sent by the RP in the authentication request
 * scope: scope sent by the RP in the authentication request
 * start_time: timestamp (seconds since 1 Jan 1970) when the transaction was initiated

This information is then passed in the SAML RelayState as an encrypted JSON Web Token (JWE).


SAML bindings
=============

Authentication request binding
------------------------------

The binding for the authentication request (sent from the SP to the IdP) is dynamically chosen based on the bindings
the IdP publishes in its metadata. The binding is chosen in order from the list below:

    #) HTTP POST
    #) HTTP Redirect

If the IdP lacks support for all bindings above, the SP throws an exception.


Authentication response request binding
---------------------------------------

At init the SP chooses the first AssertionConsumerServiceURL (index 0) in the metadata, which right now is
HTTP-Redirect.


MDX protocol
============

When fetching IdP's SAML metadata from the MDX server, the IdP's entity id is hashed with sha1 to make it url safe.
