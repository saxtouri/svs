import base64
import datetime
import hashlib
import json
import os
from urllib.parse import urlparse, parse_qsl, urlencode

import pytest
import responses
from oic.oic.message import AuthorizationRequest, AuthorizationResponse
from werkzeug.test import Client
from werkzeug.wrappers import BaseResponse

from svs.wsgi import make_app


class TestApp:
    def do_auth_flow(self):
        # get provider configuration information
        resp = self.app.get('/.well-known/openid-configuration')
        assert resp.status_code == 200
        provider_config = json.loads(resp.data.decode('utf-8'))

        # incoming auth request from client, verify response is redirect to discovery service
        auth_req = AuthorizationRequest(client_id='client1', response_type='id_token', scope='openid student',
                                        redirect_uri='http://localhost:8090/authz_cb', nonce='nonce')
        auth_url = auth_req.request(urlparse(provider_config['authorization_endpoint']).path)
        resp = self.app.get(auth_url)
        assert resp.status_code == 303
        disco_url = dict(resp.headers)['Location']
        assert disco_url.startswith('http://localhost:8080/role/idp.ds')

        # incoming disco response, verify response is auth request to IdP
        disco_resp_url = dict(parse_qsl(urlparse(disco_url).query))['return']
        with responses.RequestsMock() as rsps:
            idp_metadata = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="testProvider">
                    <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:9000/sso/redirect"/>
                    </md:IDPSSODescriptor>
                    </md:EntityDescriptor>
                    """
            rsps.add(responses.GET,
                     'http://pyff:8080/entities/%7Bsha1%7D' + hashlib.sha1('testProvider'.encode('utf-8')).hexdigest(),
                     body=idp_metadata, status=200)
            resp = self.app.get(urlparse(disco_resp_url).path + '?' + urlencode({'entityID': 'testProvider'}))

        assert resp.status_code == 303
        idp_url = dict(resp.headers)['Location']
        assert idp_url.startswith('http://localhost:9000/sso/redirect')

        # incoming authn response from IdP, verify response is consent page
        saml_response = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="{0:%Y-%m-%dT%H:%M:%SZ}" Destination="" InResponseTo="">
          <saml:Issuer>testProvider</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
          <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="{0:%Y-%m-%dT%H:%M:%SZ}">
            <saml:Issuer>testProvider</saml:Issuer>
            <saml:Subject>
              <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
              <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://localhost:10000/SAML2Transient/acs/post" InResponseTo=""/>
              </saml:SubjectConfirmation>
            </saml:Subject>
            <saml:Conditions>
              <saml:AudienceRestriction>
                <saml:Audience>http://localhost:10000/SAML2Transient/acs/post</saml:Audience>
              </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
              <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
              </saml:AuthnContext>
            </saml:AuthnStatement>
            <saml:AttributeStatement>
              <saml:Attribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue xsi:type="xs:string">student</saml:AttributeValue>
              </saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion>
        </samlp:Response>
                """.format(datetime.datetime.utcnow())
        resp = self.app.post('/SAML2Transient/acs/post',
                             data={'SAMLResponse': base64.b64encode(saml_response.encode('utf-8')),
                                   'RelayState': dict(parse_qsl(urlparse(idp_url).query))['RelayState']})
        assert resp.status_code == 200

    @pytest.fixture(autouse=True)
    def create_app(self):
        os.chdir(os.path.join(os.path.dirname(__file__), '../../config'))
        self.app = Client(make_app(), BaseResponse)

    def test_consent_css(self):
        resp = self.app.get('/consent.css')
        assert resp.status_code == 200
        assert resp.headers['Content-Type'] == 'text/css'

    def test_full_flow(self):
        self.do_auth_flow()

        # incoming accepted consent, verify response is OIDC authn response to client
        resp = self.app.get('/consent/handle_consent/allow')
        assert resp.status_code == 303
        authn_resp = AuthorizationResponse().from_urlencoded(urlparse(dict(resp.headers)['Location']).fragment)
        assert 'id_token' in authn_resp

    def test_full_flow_with_denied_user_consent(self):
        self.do_auth_flow()

        # incoming denied consent, verify response is OIDC authn error response 'access_denied'
        resp = self.app.get('/consent/handle_consent/deny')
        assert resp.status_code == 303
        authn_resp = AuthorizationResponse().from_urlencoded(urlparse(dict(resp.headers)['Location']).fragment)
        assert authn_resp['error'] == 'access_denied'
