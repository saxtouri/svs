import unittest

from jwkest.jwk import SYMKey
from oic.oauth2 import rndstr

from svs.utils import construct_state, deconstruct_state


__author__ = 'regu0004'


class RelayStateTest(unittest.TestCase):
    def test_relay_state(self):
        key = SYMKey(key=rndstr(32), kid="1")
        key.serialize()

        payload = {"state": "STATE", "nonce": "NONCE"}
        _state = construct_state(payload, key)

        transformed = deconstruct_state(_state, [key])
        assert transformed == payload
