Code samples for connecting clients to the InAcademia service
#############################################################

As described in the :doc:`usage <../usage>` of the InAcademia service, there are two steps in a
transaction: 1) making an authentication request, and 2) receiving the response. A third step should
be performed beforehand, provider configuration discovery. All these steps are described in detail
for a number of libraries/frameworks below.

Note: the following code samples are not secure enough to be used in a live production environment,
they are only intended to document the basic steps required to complete a transaction with the
InAcademia service. Additional measures should be implemented to increase the security.


Python 3: pyoidc_
=================

Setup client instance
---------------------

.. code:: python

    from oic.oic import Client
    from oic.oic.message import RegistrationResponse
    from oic.utils.authn.client import CLIENT_AUTHN_METHOD

    # create a client instance
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

    # store client registration info
    registration_info = {
        "client_id": "client1",
        "client_secret": "12345",
        "redirect_uris": ["http://example.com/callback"]
    }
    client.store_registration_info(RegistrationResponse(**registration_info))

    # fetch the provider configuration information
    client.provider_config(inacademia_url)


Make authentication request
---------------------------

.. code:: python

    from oic.oauth2 import rndstr
    from oic.oic.message import Claims, ClaimsRequest
    from oic.utils.http_util import Redirect


    # make the authentication request
    scope = "openid student" # request verification of student affiliation
    claims_request = ClaimsRequest(id_token=Claims(domain={"essential": True})) # request the additional claim 'domain'
    args = {
        "client_id": client.client_id,
        "response_type": "id_token",
        "redirect_uri": redirect_uri,
        "nonce": rndstr(),
        "scope": scope,
        "claims": claims_request
    }
    auth_req = client.construct_AuthorizationRequest(request_args=args)
    login_url = auth_req.request(client.authorization_endpoint)
    http_response = Redirect(login_url)


Receive the authencation response
---------------------------------

.. code:: python

    from oic.utils.http_util import Response

    # Send HTML page with form that POSTs the url fragment back to the server
    page = """
    <html><body>
    <form action="/parse_response" method="post">
    <input type="hidden" name="response" id="response" value=""/>
    </form>
    <script type="text/javascript">
    document.getElementById("response").value = window.location.hash.substring(1);
    document.forms[0].submit();
    </script>
    </body></html>
    """
    http_response = Response(page)

Process the authentication response server-side
-----------------------------------------------

.. code:: python

    from oic.oic.message import AuthorizationResponse
    from urllib.parse import unquote, parse_qsl

    post_data = ... # read post data from http request
    params = dict(parse_qsl(unquote(post_data)))["response"]
    authn_resp = client.parse_response(AuthorizationResponse, params, sformat="urlencoded")




Java: `Nimbus OAuth 2.0 SDK`_
=============================


Apache: `mod_auth_openidc`_
===========================

Javascript
==========


.. _pyoidc: https://github.com/rohe/pyoidc
.. _Nimbus OAuth 2.0 SDK: http://connect2id.com/products/nimbus-oauth-openid-connect-sdk
.. _mod_auth_openidc: https://github.com/pingidentity/mod_auth_openidc
