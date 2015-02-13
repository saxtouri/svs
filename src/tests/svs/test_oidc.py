import json
import os
import urllib
import cherrypy

import mock
from mock import patch
from oic.oauth2 import rndstr
from oic.oic.message import AuthorizationRequest
from oic.utils.clientdb import NoClientInfoReceivedError
import pytest

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
            raise NoClientInfoReceivedError


class TestInAcademiaOpenIDConnectFrontend(object):
    BASE_URL = "http://localhost"
    METADATA = MetadataMock(full_test_path("test_data/clients.json"))
    OP = InAcademiaOpenIDConnectFrontend(BASE_URL, METADATA)
    REQUEST_ARGS = {
        "scope": "openid student",
        "nonce": rndstr(5),
        "response_type": "id_token",
    }

    def test_verify_scope(self):
        op = TestInAcademiaOpenIDConnectFrontend.OP

        scope = ["openid", "student"]
        assert op._verify_scope(scope, "client1")
        scope = ["openid", "student", "persistent"]
        assert op._verify_scope(scope, "client1")

        # Incorrect scope with both 'persistent' and 'transient'
        scope = ["openid", "student", "persistent", "transient"]
        assert not op._verify_scope(scope, "client1")

        # Missing affiliation
        scope = ["openid", "persistent"]
        assert not op._verify_scope(scope, "client1")

        # Client permmisions: client1 is allowed, but not client2
        scope = ["openid", "student"]
        assert op._verify_scope(scope, "client1")
        assert not op._verify_scope(scope, "client2")

    def test_authn_request(self):
        client_id = "client1"
        args = {
            "client_id": client_id,
            "redirect_uri": TestInAcademiaOpenIDConnectFrontend.METADATA[client_id]["redirect_uris"][0]
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        assert TestInAcademiaOpenIDConnectFrontend.OP.verify_authn_request(AuthorizationRequest(**args).to_urlencoded())

    @patch("cherrypy.response")
    def test_unknown_client_id(self, mock_cherrypy_resp):
        args = {
            "client_id": "unknown",
            "redirect_uri": "http://unknown.com"
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert TestInAcademiaOpenIDConnectFrontend.OP.verify_authn_request(urllib.urlencode(args))

    @patch("cherrypy.response")
    def test_missing_request_args(self, mock_cherrypy_resp):
        args = {
            "client_id": "unknown",
            "redirect_uri": "http://unknown.com"
        }

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            query = urllib.urlencode(args)
            assert TestInAcademiaOpenIDConnectFrontend.OP.verify_authn_request(query)

    @patch("cherrypy.response")
    def test_missing_redirect_uri(self, mock_cherrypy_resp):
        args = {
            "client_id": "client1",
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert TestInAcademiaOpenIDConnectFrontend.OP.verify_authn_request(urllib.urlencode(args))

    @patch("cherrypy.response")
    def test_incorrect_redirect_uri(self, mock_cherrypy_resp):
        args = {
            "client_id": "client1",
            "redirect_uri": "http://noexist.com"
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)

        with pytest.raises(EndUserErrorResponse):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert TestInAcademiaOpenIDConnectFrontend.OP.verify_authn_request(urllib.urlencode(args))

    @patch("cherrypy.response")
    def test_incorrect_redirect_uri(self, mock_cherrypy_resp):
        client_id = "client1"
        args = {
            "client_id": client_id,
            "redirect_uri": TestInAcademiaOpenIDConnectFrontend.METADATA[client_id]["redirect_uris"][0]
        }
        args.update(TestInAcademiaOpenIDConnectFrontend.REQUEST_ARGS)
        args["response_type"] = "code"

        with pytest.raises(cherrypy.HTTPRedirect):
            mock_cherrypy_resp.i18n.trans.ugettext = mock.MagicMock(return_value="")
            assert TestInAcademiaOpenIDConnectFrontend.OP.verify_authn_request(urllib.urlencode(args))