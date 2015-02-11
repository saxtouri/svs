import hashlib
import json
import uuid
import datetime
import time

from jwkest.jwe import JWE, DecryptionFailed


__author__ = 'roland'


def sha1_entity_transform(entity_id):
    return "{{sha1}}{}".format(hashlib.sha1(entity_id).hexdigest())


def construct_state(payload, key, alg="A128KW", enc="A128CBC-HS256"):
    """
    Construct the SAML RelayState to send to the IdP.

    :param payload: A JSON structure
    :param keys: A SYMKey
    :param alg: The encryption algorithm
    :param enc:
    :return: A JWS
    """

    _jwe = JWE(json.dumps(payload), alg=alg, enc=enc)
    relay_state = _jwe.encrypt([key])
    return relay_state


def deconstruct_state(relay_state, keys, alg="A128KW", enc="A128CBC-HS256"):
    """
    Deconstruct the SAML RelayState (received back from the IdP).

    :param relay_state: A JWS
    :param key: A decryption key (a SYMKey instance)
    :return: The payload of the JWS
    """
    jwe = JWE(alg=alg, enc=enc)
    payload, success = jwe.decrypt(relay_state, keys)
    if success:
        return json.loads(payload)
    else:
        raise DecryptionFailed()


def get_new_error_uid():
    return str(uuid.uuid1().int)


def get_timestamp():
    return time.time()


def now():
    return datetime.datetime.now()


def N_(s):
    """
    Dummy function to mark strings for translation, but defer the actual translation for later (using the real "_()").
    :param s:
    :return:
    """
    return s
