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

More information can be found `here <pyoidc client_>`_.

Setup client instance
---------------------

.. code-block:: python

    from oic.oic import Client
    from oic.oic.message import RegistrationResponse
    from oic.utils.authn.client import CLIENT_AUTHN_METHOD

    # create a client instance
    client = Client(client_id=..., client_authn_method=CLIENT_AUTHN_METHOD)

    # fetch the provider configuration information
    client.provider_config(inacademia_url)


Make authentication request
---------------------------

.. code-block:: python

    from oic.oauth2 import rndstr
    from oic.oic.message import Claims, ClaimsRequest
    from oic.utils.http_util import Redirect


    # make the authentication request
    scope = "openid student" # request verification of student affiliation
    claims_request = ClaimsRequest(id_token=Claims(domain=None)) # request the additional claim 'domain'
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

.. code-block:: python

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

.. code-block:: python

    from oic.oic.message import AuthorizationResponse
    from urllib.parse import unquote, parse_qsl

    post_data = ... # read POST data from HTTP request
    params = dict(parse_qsl(unquote(post_data)))["response"]
    authn_resp = client.parse_response(AuthorizationResponse, params, sformat="urlencoded")
    id_token = authn_resp["id_token"]

    # ... Verify the ID Token and use its claims


Java: `Nimbus OAuth 2.0 SDK`_
=============================

More information can be found `here <Nimbus client_>`_.

Fetch provider configuration information
----------------------------------------

.. code-block:: java

    import java.io.InputStream;
    import java.net.URI;
    import java.net.URL;

    import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

    URI issuerURI = new URI(inacademiaURL);
    URL providerConfigurationURL = issuerURI.resolve(
            "/.well-known/openid-configuration").toURL();
    InputStream stream = providerConfigurationURL.openStream();
    // Read all data from URL
    String providerInfo = null;
    try (java.util.Scanner s = new java.util.Scanner(stream)) {
        providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
    }
    OIDCProviderMetadata providerMetadata = OIDCProviderMetadata
            .parse(providerInfo);

Make authentication request
---------------------------

.. code-block:: java

    import java.net.URI;

    import com.nimbusds.oauth2.sdk.ResponseType;
    import com.nimbusds.oauth2.sdk.Scope;
    import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
    import com.nimbusds.openid.connect.sdk.ClaimsRequest;
    import com.nimbusds.openid.connect.sdk.Nonce;
    import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;

    Scope studentValidationScope = new Scope("openid", "student");


    AuthenticationRequest.Builder authenticationRequest = new AuthenticationRequest.Builder(
            new ResponseType(OIDCResponseTypeValue.ID_TOKEN),
            studentValidationScope, clientID, redirectURI);

    // Request additional claim 'domain'
    ClaimsRequest claimsReq = new ClaimsRequest();
    claimsReq.addIDTokenClaim("domain");

    authenticationRequest.nonce(new Nonce()).claims(claimsReq)
            .endpointURI(providerMetadata.getAuthorizationEndpointURI());

    URI loginURL = authenticationRequest.build().toURI();

    // ... Make HTTP Redirect to loginURL


Receive the authencation response
---------------------------------

.. code-block:: java

    StringBuilder sb = new StringBuilder();
    sb.append("<html><body>");
    sb.append("<form action=\"/response\" method=\"post\">");
    sb.append("<input type=\"hidden\" name=\"response\" id=\"response\" value=\"\"/>");
    sb.append("</form>");
    sb.append("<script type=\"text/javascript\">");
    sb.append("document.getElementById(\"response\").value = window.location.hash.substring(1);");
    sb.append("document.forms[0].submit();");
    sb.append("</script>");
    sb.append("</body></html>");

    // ... Make HTTP response with sb.toString()



Process the authentication response server-side
-----------------------------------------------

.. code-block:: java

    import java.net.URI;

    import com.nimbusds.jwt.JWT;
    import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
    import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
    import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

    Map<String, String> post_data = ... // read POST data from HTTP request

    URI url = new URI("http://example.com#" + post_data.get("response"));
    AuthenticationResponse authResp = AuthenticationResponseParser.parse(url);
    AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

    JWT idToken = successResponse.getIDToken();

    // ... Verify the ID Token and use its claims

Apache: `mod_auth_openidc`_
===========================

More information can be found `here <mod_auth_openidc config_>`_.

Configuration
-------------

.. code-block:: apache

    Listen <port>
    ServerName <server name>

    LoadModule auth_openidc_module /usr/lib/apache2/modules/mod_auth_openidc.so
    LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so

    <VirtualHost _default_:*>
        OIDCProviderMetadataURL <inacademia url>/.well-known/openid-configuration
        OIDCClientID <client id>
        OIDCRedirectURI https://<hostname>:<port>/protected/authz_cb
        OIDCResponseType id_token
        OIDCScope "openid student" # request verification of student affiliation
        OIDCAuthRequestParams "claims=%7B%22id_token%22%3A%20%7B%22domain%22%3A%20null%7D%7D" # request the additional claim 'domain'

        OIDCCryptoPassphrase <secret>

        <Location /protected>
          AuthType openid-connect
          Require valid-user
        </Location>

        SSLEngine on
        SSLCertificateFile <ssl cert>
        SSLCertificateKeyFile <ssl key>
    </VirtualHost>


.. _pyoidc: https://github.com/rohe/pyoidc
.. _pyoidc client: https://github.com/rohe/pyoidc/blob/master/doc/howto/rp.rst
.. _Nimbus OAuth 2.0 SDK: http://connect2id.com/products/nimbus-oauth-openid-connect-sdk
.. _Nimbus client: http://connect2id.com/products/nimbus-oauth-openid-connect-sdk/guides/java-cookbook-for-openid-connect-public-clients
.. _mod_auth_openidc: https://github.com/pingidentity/mod_auth_openidc
.. _mod_auth_openidc config: https://github.com/pingidentity/mod_auth_openidc/wiki