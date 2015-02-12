#!/usr/bin/env python
import json
import os
import unittest
import urllib

from mock import patch
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.config import SPConfig
from saml2.entity_category.edugain import COC
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAME_FORMAT_URI, name_id_from_string

from svs.saml import SamlSp, InAcademiaSAMLBackend


def full_test_path(file_path):
    test_dir_path = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(test_dir_path, file_path)


class MetadataMock(object):
    def __init__(self, file):
        with open(file) as f:
            self.data = json.load(f)

    def service(self, entity_id, typ, service, binding=None):
        return self.data[entity_id]


class TestSamlSp(unittest.TestCase):
    BASE = "http://localhost"
    ISSUER = BASE
    SP_ENTITY_ID = "{base}_sp.xml".format(base=BASE)
    ACS_ENDPOINT = "{base}/acs/redirect".format(base=BASE)
    DISCO_ENDPOINT = "{base}/disco".format(base=BASE)
    DISCO_SRV_URL = "https://ds.example.com"
    METADATA = MetadataMock(full_test_path("test_data/idps.md"))

    @classmethod
    def setUpClass(cls):
        CONFIG = {
            "name": "InAcademia SP",
            "entityid": TestSamlSp.SP_ENTITY_ID,
            'entity_category': [COC],
            "description": "InAcademia SP",
            "service": {
                "sp": {
                    "required_attributes": ["edupersonaffiliation"],
                    "endpoints": {
                        "assertion_consumer_service": [
                            (TestSamlSp.ACS_ENDPOINT, BINDING_HTTP_REDIRECT),
                        ],
                        "discovery_response": [
                            (TestSamlSp.DISCO_ENDPOINT, BINDING_DISCO)
                        ]
                    },
                    "name_id_format": [NAMEID_FORMAT_PERSISTENT]
                },
            },
            "key_file": full_test_path("test_data/certs/key.pem"),
            "cert_file": full_test_path("test_data/certs/cert.pem"),
            "name_form": NAME_FORMAT_URI,
        }

        cls.SP_CONF = SPConfig().load(CONFIG)

    def setUp(self):
        self.SP = SamlSp(None, TestSamlSp.SP_CONF, TestSamlSp.DISCO_SRV_URL, sign_func=None)

    def test_authn_request(self):
        # Check the correct HTTP-POST binding is used
        idp_entity_id = "idp_post"
        request, binding = self.SP.construct_authn_request(idp_entity_id, TestSamlSp.METADATA, TestSamlSp.ISSUER,
                                                           self.SP.nameid_policy,
                                                           TestSamlSp.ACS_ENDPOINT)
        assert request is not None
        assert binding == BINDING_HTTP_POST

        # Check the correct HTTP-Redirect binding is used
        idp_entity_id = "idp_redirect"
        request, binding = self.SP.construct_authn_request(idp_entity_id, TestSamlSp.METADATA, TestSamlSp.ISSUER,
                                                           self.SP.nameid_policy,
                                                           TestSamlSp.ACS_ENDPOINT)
        assert request is not None
        assert binding == BINDING_HTTP_REDIRECT

        # Check that HTTP-POST is preferred over HTTP-Redirect
        idp_entity_id = "idp_post_redirect"
        request, binding = self.SP.construct_authn_request(idp_entity_id, TestSamlSp.METADATA, TestSamlSp.ISSUER,
                                                           self.SP.nameid_policy,
                                                           TestSamlSp.ACS_ENDPOINT)
        assert request is not None
        assert binding == BINDING_HTTP_POST

    def test_redirect_msg(self):
        idp_entity_id = "idp_redirect"
        msg = self.SP.redirect_to_auth(TestSamlSp.METADATA, idp_entity_id, "RELAY_STATE")
        assert msg.status == "303 See Other"

    def test_post_msg(self):
        idp_entity_id = "idp_post"
        msg = self.SP.redirect_to_auth(TestSamlSp.METADATA, idp_entity_id, "RELAY_STATE")
        assert msg.status == "200 OK"
        assert "<input type=\"hidden\" name=\"SAMLRequest\"" in msg.message
        assert "<input type=\"hidden\" name=\"RelayState\"" in msg.message

    def test_disco_query(self):
        state = "test_state"
        redirect_url = self.SP.disco_query(state)

        expected_return_url = "{}?state={}".format(TestSamlSp.DISCO_ENDPOINT, state)
        assert redirect_url == "{disco_url}?entityID={entity_id}&return={return_url}".format(
            disco_url=TestSamlSp.DISCO_SRV_URL, entity_id=urllib.quote(TestSamlSp.SP_ENTITY_ID, safe=''),
            return_url=urllib.quote(expected_return_url, safe=''))


class TestGetNameID(unittest.TestCase):
    TRANSIENT_ID = "transient_id"
    PERSISTENT_ID = "persistent_id"
    EPTID = "eptid"
    EPPN = "eppn"

    TRANSIENT_NAME_ID = name_id_from_string(
        "<ns0:NameID xmlns:ns0=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">{id}</ns0:NameID>".format(
            id=TRANSIENT_ID))
    PERSISTENT_NAME_ID = name_id_from_string(
        "<ns0:NameID xmlns:ns0=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{id}</ns0:NameID>".format(
            id=PERSISTENT_ID))

    SP = InAcademiaSAMLBackend("http://localhost", None, "")

    def test_transient_NameID(self):
        # Transient id when specified in scope
        id = TestGetNameID.SP.get_name_id(TestGetNameID.TRANSIENT_NAME_ID, {}, ["openid", "transient"])
        assert id == TestGetNameID.TRANSIENT_ID

        # Transient id as default (without being specified in scope)
        id = TestGetNameID.SP.get_name_id(TestGetNameID.TRANSIENT_NAME_ID, {}, ["openid"])
        assert id == TestGetNameID.TRANSIENT_ID

        # No name id if IdP only provided persistent id
        id = TestGetNameID.SP.get_name_id(TestGetNameID.PERSISTENT_ID, {}, ["openid"])
        assert id is None

    def test_persistent_NameID(self):
        scope = ["openid", "persistent"]
        identity = {}

        # Persistent id when specified in scope
        id = TestGetNameID.SP.get_name_id(TestGetNameID.PERSISTENT_NAME_ID, identity, scope)
        assert id == TestGetNameID.PERSISTENT_ID

        # No name id if IdP can not supply persistent name id/EPTID/EPPN
        id = TestGetNameID.SP.get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
        assert id is None

        # Use EPTID instead of persistent id
        with patch.dict(identity, {"eduPersonTargetedID": [TestGetNameID.EPTID]}):
            id = TestGetNameID.SP.get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
            assert id == TestGetNameID.EPTID

        # Use EPPN instead of persistent id
        with patch.dict(identity, {"eduPersonPrincipalName": [TestGetNameID.EPPN]}):
            id = TestGetNameID.SP.get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
            assert id == TestGetNameID.EPPN

        # Prioritize EPTID (over EPPN)
        with patch.dict(identity,
                        {"eduPersonTargetedID": [TestGetNameID.EPTID], "eduPersonPrincipalName": [TestGetNameID.EPPN]}):
            id = TestGetNameID.SP.get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
            assert id == TestGetNameID.EPTID