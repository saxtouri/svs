import unittest

from saml2.saml import name_id_from_string
from mock import patch

from svs.filter import get_name_id


__author__ = 'regu0004'


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


    def test_transient_NameID(self):
        # Transient id when specified in scope
        id = get_name_id(TestGetNameID.TRANSIENT_NAME_ID, {}, ["openid", "transient"])
        assert id == TestGetNameID.TRANSIENT_ID

        # Transient id as default (without being specified in scope)
        id = get_name_id(TestGetNameID.TRANSIENT_NAME_ID, {}, ["openid"])
        assert id == TestGetNameID.TRANSIENT_ID

        # No name id if IdP only provided persistent id
        id = get_name_id(TestGetNameID.PERSISTENT_ID, {}, ["openid"])
        assert id is None

    def test_persistent_NameID(self):
        scope = ["openid", "persistent"]
        identity = {}

        # Persistent id when specified in scope
        id = get_name_id(TestGetNameID.PERSISTENT_NAME_ID, identity, scope)
        assert id == TestGetNameID.PERSISTENT_ID

        # No name id if IdP can not supply persistent name id/EPTID/EPPN
        id = get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
        assert id is None

        # Use EPTID instead of persistent id
        with patch.dict(identity, {"eduPersonTargetedID": [TestGetNameID.EPTID]}):
            id = get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
            assert id == TestGetNameID.EPTID

        # Use EPPN instead of persistent id
        with patch.dict(identity, {"eduPersonPrincipalName": [TestGetNameID.EPPN]}):
            id = get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
            assert id == TestGetNameID.EPPN

        # Prioritize EPTID (over EPPN)
        with patch.dict(identity,
                        {"eduPersonTargetedID": [TestGetNameID.EPTID], "eduPersonPrincipalName": [TestGetNameID.EPPN]}):
            id = get_name_id(TestGetNameID.TRANSIENT_NAME_ID, identity, scope)
            assert id == TestGetNameID.EPTID

