import logging

from oic.oauth2 import VerificationError
from oic.utils.http_util import SeeOther
from oic.utils.http_util import Response
from saml2.client_base import Base
from saml2.saml import Issuer, NAMEID_FORMAT_ENTITY
from saml2.samlp import AuthnRequest
from saml2.samlp import NameIDPolicy
from saml2.time_util import instant
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.s_utils import sid
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding

from log_utils import log_internal


logger = logging.getLogger(__name__)


class ServiceErrorException(Exception):
    pass


class AuthnFailure(ServiceErrorException):
    pass


class SamlSp(object):
    def __init__(self, srv, conf, metadata, disco_srv, force_authn=False,
                 sign_func=None):
        """
        Constructor for the class.
        :param srv: Usually none, but otherwise the server.
        :param conf: The SAML SP configuration
        :param metadata: MetaData instance
        :param disco_srv: The address to the DiscoServer
        :param sign_func: A function that signs a SAML message
        """

        self.srv = srv
        self.idp_query_param = "IdpQuery"
        self.conf = conf
        self.mds = metadata
        self.disco_srv = disco_srv
        self.force_authn = force_authn
        self.sign_func = sign_func

        # returns list of 2-tuples (endpoint, binding)
        acs = self.conf.getattr("endpoints", "sp")["assertion_consumer_service"]
        # Should only be one

        self.response_binding = acs[0][1]
        self.response_url = acs[0][0]

        # Can be regarded as static, will seldom if ever change
        _cargs = {
            "format": self.conf.getattr("name_id_format", "sp")[0],
            "allow_create": "false"
        }
        self.nameid_policy = NameIDPolicy(**_cargs)

        # This is a simple SP
        self.sp = Base(conf)
        self.sp.sec.metadata = metadata

        # Since I probably didn't send the original request at least I can't
        # count on it.
        self.sp.allow_unsolicited = True
        self.sp.config.entityid = self.conf.entityid
        self.issuer = Issuer(text=self.conf.entityid,
                             format=NAMEID_FORMAT_ENTITY)

    def construct_authn_request(self, idp_entity_id, mds, nameid_policy,
                                assertion_consumer_service_url="",
                                assertion_consumer_service_index=""):
        """

        :param idp_entity_id: Which IdP to send the request to
        :param mds: MetaData instance
        :param nameid_policy: A NameIDPolicy instance
        :param assertion_consumer_service_url: Assertion consumer endpoint
        :param assertion_consumer_service_index: Assertion consumer endpoint
        reference
        :return: AuthnRequest instance
        """
        destinations = mds.service(idp_entity_id, "idpsso_descriptor",
                                   "single_sign_on_service")

        if destinations is None:
            raise ServiceErrorException("IdP '{}' not known in MDX".format(idp_entity_id))

        binding = None
        if BINDING_HTTP_POST in destinations:
            binding = BINDING_HTTP_POST
        elif BINDING_HTTP_REDIRECT in destinations:
            binding = BINDING_HTTP_REDIRECT

        if binding is None:
            raise ServiceErrorException("IdP does not support http-post or http-redirect binding")

        location = destinations[binding][0]["location"]
        arg = {"destination": location}

        if assertion_consumer_service_url:
            arg["assertion_consumer_service_url"] = assertion_consumer_service_url
            arg["protocol_binding"] = self.response_binding
        if assertion_consumer_service_index:
            arg["assertion_consumer_service_index"] = assertion_consumer_service_index

        if self.force_authn:
            _force = "true"
        else:
            _force = "false"

        return AuthnRequest(
            id=sid(), version="2.0", issue_instant=instant(),
            issuer=self.issuer, name_id_policy=nameid_policy,
            force_authn=_force, **arg), binding

    def parse_auth_response(self, SAMLResponse, binding):
        """
        Verifies if the authentication was successful.
        Verifying the RelayState has happened before this method is called.

        :param SAMLResponse: The SAML Response from the IdP
        :return: If the authentication was successful a tuple containing
        the nameID text field and the Identity information. Otherwise an
        AuthnFailure exception.
        """

        if not SAMLResponse:
            logger.info("Missing Response")
            raise AuthnFailure("You are not authorized!")

        try:
            _response = self.sp.parse_authn_request_response(SAMLResponse, binding)
        except UnknownPrincipal as exp:
            logger.error("UnknownPrincipal: %s" % (exp,))
            raise
        except UnsupportedBinding as exp:
            logger.error("UnsupportedBinding: %s" % (exp,))
            raise
        except VerificationError as err:
            logger.error("Verification error: %s" % (err,))
            raise
        except Exception as err:
            logger.error("Other error: %s" % (err,))
            raise

        # logger.info("parsed OK")'
        return (_response.assertion.subject.name_id, _response.ava,
                _response.assertion.authn_statement[0].authn_instant, _response.assertion.issuer.text)

    def parse_disco_response(self, query_part):
        """
        Parse a discovery service response and return only the entity_id
        of the choose IdP

        :param query_part: The query part of the return URL
        :return: The IdP entity ID or "" if none given
        """
        return self.sp.parse_discovery_service_response(query=query_part)

    def disco_query(self, state):
        """
        This service is expected to always use a discovery service. This is
        where the response is handled

        :param state: State variable, a JWS
        :return:
        """

        _cli = self.sp

        eid = _cli.config.entityid
        # returns list of 2-tuples
        dr = self.conf.getattr("endpoints", "sp")["discovery_response"]
        # The first value of the first tuple is the one I want
        ret = dr[0][0]
        # append it to the disco server URL
        ret += "?state=%s" % state
        loc = _cli.create_discovery_service_request(
            self.disco_srv, eid, **{"return": ret})

        return loc

    def redirect_to_auth(self, entity_id, relay_state):
        """
        Creates the redirect message that will redirect the user to the IdP
        for authentication.

        :param entity_id: The entity ID of the IdP that should do the
        authentication.
        :param relay_state: A JWE containing state information
        :return:
        """
        request, binding = self.construct_authn_request(entity_id, self.mds,
                                                        self.nameid_policy,
                                                        self.response_url)
        log_internal(logger, "saml_authn_request {}".format(str(request).replace('\n', '')), None,
                     transaction_id=relay_state)

        if self.sign_func:
            msg_str = self.sign_func(request)
        else:
            msg_str = "%s" % request

        ht_args = self.sp.apply_binding(binding, msg_str,
                                        request.destination,
                                        relay_state=relay_state)

        if binding == BINDING_HTTP_REDIRECT:
            for param, value in ht_args["headers"]:
                if param == "Location":
                    resp = SeeOther(str(value))
                    break
            else:
                raise ServiceErrorException("Parameter error")
        else:
            resp = Response(''.join(ht_args["data"]), headers=ht_args["headers"])

        return resp
