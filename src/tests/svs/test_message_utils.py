import logging
import urlparse
import cherrypy
from jwkest.jwk import SYMKey
from mock import MagicMock
from oic.oauth2 import rndstr
import pytest
import time
from svs.message_utils import negative_transaction_response
from svs.utils import construct_state

__author__ = 'regu0004'


class TestNegativeTransaction(object):
    def test_negative_transaction(self):
        state = "STATE"
        error_msg = "Error message test"
        logger = logging.getLogger()
        key = SYMKey(key=rndstr(32), kid="1")
        key.serialize()

        transaction_session = {"state": state, "nonce": "NONCE",
                               "start_time": time.time(),
                               "client_id": "client1",
                               "redirect_uri": "https://example.com"}
        transaction_id = construct_state(transaction_session, key)

        environ = MagicMock()

        with pytest.raises(cherrypy.HTTPRedirect) as redirect:
            negative_transaction_response(transaction_id, transaction_session,
                                          environ, logger, error_msg,
                                          "test_idp_entity")

        response = urlparse.parse_qs(urlparse.urlparse(redirect.value.urls[0]).fragment)
        assert response["state"][0] == state
        assert response["error"][0] == "access_denied"
        assert response["error_description"][0] == error_msg