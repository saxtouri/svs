#!/usr/bin/env python

import unittest

from jwkest.jwk import SYMKey
from oic.oauth2 import rndstr
from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import SPConfig
from saml2.entity_category.edugain import COC
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAME_FORMAT_URI

from metadata import LocalMetadata
from saml import SamlSp
from utils import construct_state
from utils import deconstruct_state


__author__ = 'roland'


class RelayStateTest(unittest.TestCase):
    def test_relay_state(self):
        symkey = rndstr(32)

        key = SYMKey(key=symkey, kid="1")
        key.serialize()

        payload = {"state": "STATE", "nonce": "NONCE"}

        _state = construct_state(payload, key)

        transformed = deconstruct_state(_state, [key])

        # info is a tuple: (payload, decode_success)
        self.assertEqual(transformed, payload)


class SamlSpTest(unittest.TestCase):
    BASE = "localhost"
    MetadataFunc = LocalMetadata({"mdfile": ["Sweden.md"]})
    IDP_ENTITY_ID = "https://idp.umu.se/saml2/idp/metadata.php"
    ACS_URL = "%sacs/redirect" % BASE
    ISSUER = BASE

    CONFIG = {
        "name": "InAcademia SP",
        "entityid": "%s%ssp.xml" % (BASE, ""),
        'entity_category': [COC],
        "description": "InAcademia SP",
        "service": {
            "sp": {
                "required_attributes": ["edupersonaffiliation"],
                "endpoints": {
                    "assertion_consumer_service": [
                        (ACS_URL, BINDING_HTTP_REDIRECT),
                    ],
                    "discovery_response": [
                        ("%sdisco" % BASE, BINDING_DISCO)
                    ]
                },
                "name_id_format": [NAMEID_FORMAT_PERSISTENT]
            },
        },
        "key_file": "pki/mykey.pem",
        "cert_file": "pki/mycert.pem",
        "name_form": NAME_FORMAT_URI,
    }
    SP_CONF = SPConfig().load(CONFIG)


    def setUp(self):
        self.SP = SamlSp(None, SamlSpTest.SP_CONF, SamlSpTest.MetadataFunc, {}, sign_func=None)

    def test_authn_request(self):
        request = self.SP.construct_authn_request(
            SamlSpTest.IDP_ENTITY_ID, self.SP.mds, SamlSpTest.ISSUER, self.SP.nameid_policy,
            SamlSpTest.ACS_URL)

        self.assertIsNotNone(request)

    def test_redirect_msg(self):
        msg = self.SP.redirect_to_auth(SamlSpTest.IDP_ENTITY_ID, "RELAY_STATE")
        self.assertEqual(msg.status, "303 See Other")


if __name__ == '__main__':
    unittest.main()