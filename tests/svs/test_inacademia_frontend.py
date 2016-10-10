import json
import os
from datetime import datetime
from unittest.mock import Mock
from urllib.parse import urlparse

import pytest
from jwkest.jwk import RSAKey, rsa_load
from oic.oic.message import AuthorizationRequest, ClaimsRequest, Claims, AuthorizationResponse, \
    AuthorizationErrorResponse, IdToken
from pyop.exceptions import InvalidAuthenticationRequest
from saml2.cert import OpenSSLWrapper
from satosa.internal_data import InternalResponse, AuthenticationInformation

from svs.inacademia_frontend import scope_is_valid_for_client, claims_request_is_valid_for_client, InAcademiaFrontend


@pytest.fixture(scope='session')
def signing_key_path(tmpdir_factory):
    tmpdir = str(tmpdir_factory.getbasetemp())
    path = os.path.join(tmpdir, 'sign_key.pem')
    _, private_key = generate_cert()

    with open(path, 'wb') as f:
        f.write(private_key)

    return path


def generate_cert():
    cert_info = {
        'cn': 'localhost',
        'country_code': 'se',
        'state': 'ac',
        'city': 'Umea',
        'organization': 'ITS',
        'organization_unit': 'DIRG'
    }
    osw = OpenSSLWrapper()
    cert_str, key_str = osw.create_certificate(cert_info, request=False)
    return cert_str, key_str


class TestScopeIsValidForClient:
    @pytest.mark.parametrize('scope, allowed_scope_values', [
        ('openid student', ['student', 'transient']),
        ('openid student persistent', ['student', 'persistent'])
    ])
    def test_valid_scope(self, scope, allowed_scope_values):
        client_id = 'client1'
        provider = Mock()
        provider.clients = {client_id: {'allowed_scope_values': allowed_scope_values}}
        auth_req = AuthorizationRequest(scope=scope, client_id=client_id)

        # should not raise an exception
        scope_is_valid_for_client(provider, auth_req)

    def test_invalid_scope_missing_affiliation(self):
        auth_req = AuthorizationRequest(scope='openid persistent')
        with pytest.raises(InvalidAuthenticationRequest):
            scope_is_valid_for_client(None, auth_req)

    def test_invalid_scope_with_both_persistent_and_transient(self):
        auth_req = AuthorizationRequest(scope='openid transient persistent')
        with pytest.raises(InvalidAuthenticationRequest):
            scope_is_valid_for_client(None, auth_req)

    def test_scope_not_allowed_for_client(self):
        client_id = 'client1'
        provider = Mock()
        provider.clients = {client_id: {'allowed_scope_values': []}}

        auth_req = AuthorizationRequest(scope='openid alum', client_id=client_id)
        with pytest.raises(InvalidAuthenticationRequest):
            scope_is_valid_for_client(provider, auth_req)

    def test_default_transient_not_allowed(self):
        client_id = 'client1'
        provider = Mock()
        provider.clients = {client_id: {'allowed_scope_values': ['student']}}

        auth_req = AuthorizationRequest(scope='openid student', client_id=client_id)
        with pytest.raises(InvalidAuthenticationRequest):
            scope_is_valid_for_client(provider, auth_req)

class TestClaimsRequestIsValidForClient:
    def test_valid_claims_request_for_client(self):
        client_id = 'client1'
        provider = Mock()
        provider.clients = {client_id: {'allowed_claims': ['domain']}}

        auth_req = AuthorizationRequest(claims=ClaimsRequest(id_token=Claims(domain=None)), client_id=client_id)
        # should not raise an exception
        claims_request_is_valid_for_client(provider, auth_req)

    def test_request_without_claims_request(self):
        auth_req = AuthorizationRequest()
        # should not raise an exception
        claims_request_is_valid_for_client(None, auth_req)

    def test_claims_request_not_allowed_for_client(self):
        client_id = 'client1'
        provider = Mock()
        provider.clients = {client_id: {'allowed_claims': []}}

        auth_req = AuthorizationRequest(claims=ClaimsRequest(id_token=Claims(domain=None)), client_id=client_id)
        with pytest.raises(InvalidAuthenticationRequest):
            claims_request_is_valid_for_client(provider, auth_req)

    def test_claims_request_for_userinfo_claims(self):
        auth_req = AuthorizationRequest(claims=ClaimsRequest(userinfo=Claims(domain=None)))
        with pytest.raises(InvalidAuthenticationRequest):
            claims_request_is_valid_for_client(None, auth_req)


class TestInAcademiaFrontend:
    @pytest.fixture
    def client_db_path(self, tmpdir):
        client_db = {'client1': {
            'response_types': ['id_token'],
            'redirect_uris': ['https://client.example.com']
        }}
        client_db_path = os.path.join(str(tmpdir), 'client_db.json')
        with open(client_db_path, 'w') as f:
            f.write(json.dumps(client_db))

        return client_db_path

    @pytest.fixture(autouse=True)
    def create_frontend(self, client_db_path, signing_key_path):
        internal_attributes = {
            'attributes':
                {'affiliation': {'openid': ['affiliation']}}
        }

        config = {'client_db_path': client_db_path, 'signing_key_path': signing_key_path}

        self.frontend = InAcademiaFrontend(lambda: None, internal_attributes, config,
                                           base_url='https://satosa.example.com',
                                           name='InAcademiaFrontend')
        self.frontend.register_endpoints(['test_backend'])

    @pytest.mark.parametrize('scope_value, affiliation', [
        ('student', 'student'),
        ('employee', 'employee'),
        ('alum', 'alum'),
        ('affiliated', 'student'),
        ('affiliated', 'employee'),
        ('affiliated', 'member'),
        ('faculty+staff', 'faculty'),
        ('faculty+staff', 'staff'),
    ])
    def test_handle_authn_response_returns_id_token_for_verified_affiliation(
            self, signing_key_path, context, scope_value, affiliation):
        authn_req = AuthorizationRequest(scope='openid ' + scope_value, client_id='client1',
                                         redirect_uri='https://client.example.com',
                                         response_type='id_token')
        context.state[self.frontend.name] = {'oidc_request': authn_req.to_urlencoded()}
        internal_response = InternalResponse(AuthenticationInformation(None, str(datetime.now()),
                                                                       'https://idp.example.com'))
        internal_response.attributes['affiliation'] = [affiliation]
        internal_response.user_id = 'user1'

        resp = self.frontend.handle_authn_response(context, internal_response)
        auth_resp = AuthorizationResponse().from_urlencoded(urlparse(resp.message).fragment)

        id_token = IdToken().from_jwt(auth_resp['id_token'], key=[RSAKey(key=rsa_load(signing_key_path))])
        assert id_token['iss'] == self.frontend.base_url
        assert id_token['aud'] == ['client1']
        assert id_token['auth_time'] == internal_response.auth_info.timestamp

    @pytest.mark.parametrize('scope_value, affiliation', [
        ('student', 'employee'),
        ('employee', 'student'),
        ('alum', 'student'),
        ('affiliated', 'alum'),
        ('faculty+staff', 'employee'),
    ])
    def test_handle_authn_response_returns_error_access_denied_for_wrong_affiliation(self, context, scope_value,
                                                                                     affiliation):
        authn_req = AuthorizationRequest(scope='openid ' + scope_value, client_id='client1',
                                         redirect_uri='https://client.example.com',
                                         response_type='id_token')
        context.state[self.frontend.name] = {'oidc_request': authn_req.to_urlencoded()}
        internal_response = InternalResponse()
        internal_response.attributes['affiliation'] = [affiliation]
        internal_response.user_id = 'user1'

        resp = self.frontend.handle_authn_response(context, internal_response)
        auth_resp = AuthorizationErrorResponse().from_urlencoded(urlparse(resp.message).fragment)
        assert auth_resp['error'] == 'access_denied'
