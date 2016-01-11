import json
import os
import urllib
import urlparse
from time import strftime, gmtime

import cherrypy

import mock
import time

from math import ceil
from mock import patch
from oic.oauth2 import rndstr
from oic.oic.message import AuthorizationRequest, IdToken
from oic.utils.clientdb import NoClientInfoReceivedError
import pytest
from oic.utils.time_util import TIME_FORMAT

from svs.oidc import InAcademiaOpenIDConnectFrontend
from svs.user_interaction import EndUserErrorResponse

__author__ = 'regu0004'


def full_test_path(file_path):
    test_dir_path = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(test_dir_path, file_path)


class MetadataMock(object):
    def __init__(self, file):
        with open(file) as f:
            self.data = json.load(f)

    def __getitem__(self, item):
        try:
            return self.data[item]
        except KeyError:
            raise NoClientInfoReceivedError("test")


@pytest.fixture(scope="session")
def metadata_mock():
    return MetadataMock(full_test_path("test_data/clients.json"))


@patch("cherrypy.response")
class TestInAcademiaOpenIDConnectFrontend(object):
    REQUEST_ARGS = {
        "scope": "openid student",
        "nonce": rndstr(5),
        "response_type": "id_token",
    }

    @pytest.fixture(autouse=True)
    def create_frontend(self, metadata_mock):
        self.op = InAcademiaOpenIDConnectFrontend("http://localhost", metadata_mock)

    def test_verify_scope(self, mock_cherrypy_resp):
        scope = ["openid", "student"]
        assert self.op._verify_scope(scope, "client1")
        scope = ["openid", "student", "persistent"]
        assert self.op._verify_scope(scope, "client1")

        # Incorrect scope with both 'persistent' and 'transient'
        scope = ["openid", "student", "persistent", "transient"]
        assert not self.op._verify_scope(scope, "client1")

        # Missing affiliation
        scope = ["openid", "persistent"]
        assert not self.op._verify_scope(scope, "client1")

        # Client permmisions: client1 is allowed, but not client2
        scope = ["openid", "student"]
        assert self.op._verify_scope(scope, "client1")
        assert not self.op._verify_scope(scope, "client2")

    def test_authn_request(self, mock_cherrypy_resp, metadata_mock):
        client_id = "client1"
        args = {
            "client_id": client_id,
            "redirect_uri": metadata_mock[client_id]["redirect_uris"][0]
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        resp = self.op.verify_authn_request(AuthorizationRequest(**args).to_urlencoded())
        assert resp["client_id"] == client_id

    def test_missing_nonce(self, mock_cherrypy_resp, metadata_mock):
        client_id = "client1"
        args = {
            "client_id": client_id,
            "redirect_uri": metadata_mock[client_id]["redirect_uris"][0]
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)
        del args["nonce"]

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            self.op.verify_authn_request(AuthorizationRequest(**args).to_urlencoded())

    def test_extra_claims(self, mock_cherrypy_resp):
        test_country = "Atlantis"
        test_organization = "SuperCorp"
        test_idp = "test_idp"
        kwargs = {
            "user_id": "foo",
            "affiliation": "student",
            "identity": {"eduPersonAffiliation": "student",
                         "schacHomeOrganization": [test_organization]},
            "auth_time": "1970-01-01T00:00:00Z",
            "idp_entity_id": test_idp,
            "idp_metadata_func": {test_idp: {"country": test_country}}
        }

        # Request country
        session = {"client_id": "client2", "claims": {"country": None}}
        claims = self.op.get_claims_to_release(transaction_session=session, **kwargs)
        assert claims["Country"] == test_country

        # Request country, but not allowed
        session = {"client_id": "client1", "claims": {"country": None}}
        claims = self.op.get_claims_to_release(transaction_session=session, **kwargs)
        assert "Country" not in claims

        # Request domain
        session = {"client_id": "client1", "claims": {"domain": None}}
        claims = self.op.get_claims_to_release(transaction_session=session, **kwargs)
        assert claims["Domain"] == test_organization

        # Request domain, but not allowed
        session = {"client_id": "client2", "claims": {"domain": None}}
        claims = self.op.get_claims_to_release(transaction_session=session, **kwargs)
        assert "Domain" not in claims

    def test_unknown_client_id(self, mock_cherrypy_resp):
        args = {
            "client_id": "unknown",
            "redirect_uri": "http://unknown.com"
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert self.op.verify_authn_request(urllib.urlencode(args))

    def test_missing_request_args(self, mock_cherrypy_resp):
        args = {
            "client_id": "unknown",
            "redirect_uri": "http://unknown.com"
        }

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            query = urllib.urlencode(args)
            assert self.op.verify_authn_request(query)

    def test_missing_redirect_uri(self, mock_cherrypy_resp):
        args = {
            "client_id": "client1",
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert self.op.verify_authn_request(urllib.urlencode(args))

    def test_incorrect_redirect_uri(self, mock_cherrypy_resp):
        args = {
            "client_id": "client1",
            "redirect_uri": "http://noexist.com"
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert self.op.verify_authn_request(urllib.urlencode(args))

    def test_incorrect_response_type(self, mock_cherrypy_resp, metadata_mock):
        client_id = "client1"
        args = {
            "client_id": client_id,
            "redirect_uri": metadata_mock[client_id]["redirect_uris"][0]
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)
        args["response_type"] = "code"

        with pytest.raises(cherrypy.HTTPRedirect):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert self.op.verify_authn_request(urllib.urlencode(args))

    def test_error_message_invalid_scope(self, mock_cherrypy_resp, metadata_mock):
        client_id = "client1"
        scope = "openid invalid_foobar"
        state = "test_state"
        args = {
            "client_id": client_id,
            "redirect_uri": metadata_mock[client_id]["redirect_uris"][0],
            "state": state
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)
        args["scope"] = scope
        with pytest.raises(cherrypy.HTTPRedirect) as redirect:
            self.op.verify_authn_request(AuthorizationRequest(**args).to_urlencoded())

        response = urlparse.parse_qs(urlparse.urlparse(redirect.value.urls[0]).fragment)
        error_desc = urllib.unquote_plus(response["error_description"][0])
        assert scope in error_desc
        assert response["state"][0] == state

    def test_employee_scope(self, mock_cherrypy_resp):
        scope = ["openid", "employee"]
        assert self.op._verify_scope(scope, "client3")

    def test_id_token_expiration(self, mock_cherrypy_resp):
        transaction_session = {
            "redirect_uri": "http://client.example.com",
            "client_id": "client1",
            "start_time": time.time()
        }

        with pytest.raises(cherrypy.HTTPRedirect) as redirect:
            self.op.id_token({
                "Identifier": "foobar",
                "Authentication time": strftime(TIME_FORMAT, gmtime())
            }, "http://idp.example.com", None, transaction_session)

        response = urlparse.parse_qs(urlparse.urlparse(redirect.value.urls[0]).fragment)
        id_token = IdToken().from_jwt(response["id_token"][0], verify=False)
        assert ceil(id_token["exp"] - time.time()) == 1800
