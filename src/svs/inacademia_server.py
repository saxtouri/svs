import hashlib
import json
import logging.config
import os
import urllib
import urlparse
import time

import cherrypy
from oic.utils.http_util import Redirect, SeeOther
from oic.utils.time_util import str_to_time
from oic.utils.clientdb import MDQClient, NoClientInfoReceivedError
from oic.oauth2.message import MissingRequiredAttribute
from oic.oic.message import AuthorizationRequest, AuthorizationResponse, AuthorizationErrorResponse
from oic.oic.provider import Provider
from oic.utils.keyio import KeyBundle, KeyJar, keybundle_from_local_file, dump_jwks
from oic.utils.webfinger import WebFinger, OIC_ISSUER
from saml2.config import SPConfig
from saml2.httpbase import HTTPBase
from saml2.mdstore import MetaDataMDX
from saml2.response import DecryptionFailed
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, saml
from saml2 import sigver, md, config
from saml2.attribute_converter import ac_factory
from saml2.extension import mdui, dri, mdattr, ui, idpdisc
from saml2.sigver import security_context
import xmldsig
import xmlenc

from .user_interaction import EndUserErrorResponse, LOOKUP
from .i18n_tool import ugettext as _
from .sp_metadata import make_metadata, PERSISTENT_SP_KEY, TRANSIENT_SP_KEY
from .filter import AFFILIATIONS, PERSISTENT_NAMEID, TRANSIENT_NAMEID, get_affiliation_function, get_name_id, COUNTRY, \
    DOMAIN, AFFILIATION_ATTRIBUTE
from .log_utils import log_transaction_fail, log_transaction_start, log_transaction_idp, log_internal, \
    log_transaction_success, log_transaction_aborted
from .saml import SamlSp, AuthnFailure
from .saml import ServiceErrorException
from .utils import get_timestamp, sha1_entity_transform, deconstruct_state, now, get_new_error_uid, \
    construct_state, N_


__author__ = 'regu0004'

logger = logging.getLogger(__name__)


def setup_logging(config_dict=None, default_path='logging_conf.json', default_level=logging.INFO, env_key='LOG_CFG'):
    """Setup logging configuration"""

    if config_dict is not None:
        logging.config.dictConfig(config_dict)
    else:
        path = default_path
        value = os.getenv(env_key, None)
        if value:
            path = value
        if os.path.exists(path):
            with open(path, 'rt') as f:
                config = json.load(f)
            logging.config.dictConfig(config)
        else:
            logging.basicConfig(level=default_level)


def main():
    import argparse
    import pkg_resources

    parser = argparse.ArgumentParser()
    parser.add_argument("--mdx", dest="mdx", required=True, type=str, help="base url to the MDX server")
    parser.add_argument("--cdb", dest="cdb", required=True, type=str, help="base url to the client database server")
    parser.add_argument("-b", dest="base", required=True, type=str, help="base url for the service")
    parser.add_argument("-H", dest="host", default="0.0.0.0", type=str, help="host for the service")
    parser.add_argument("-p", dest="port", default=8087, type=int, help="port for the service to listen on")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--disco", dest="disco_url", type=str, help="base url to the discovery server")
    group.add_argument("--idp", dest="idp_entity_id", type=str, help="base url to the discovery server")

    args = parser.parse_args()

    with open("conf/logging_conf.json", "r") as f:
        logging_conf = json.load(f)
    setup_logging(config_dict=logging_conf)

    # add directory to PATH environment variable to find xmlsec
    os.environ["PATH"] += os.pathsep + '/usr/local/bin'

    ONTS = {
        saml.NAMESPACE: saml,
        mdui.NAMESPACE: mdui,
        mdattr.NAMESPACE: mdattr,
        dri.NAMESPACE: dri,
        ui.NAMESPACE: ui,
        idpdisc.NAMESPACE: idpdisc,
        md.NAMESPACE: md,
        xmldsig.NAMESPACE: xmldsig,
        xmlenc.NAMESPACE: xmlenc
    }

    ATTRCONV = ac_factory("")
    sec_config = config.Config()
    sec_config.xmlsec_binary = sigver.get_xmlsec_binary()

    logger.debug("xmlsec binary: {}".format(sec_config.xmlsec_binary))

    http = HTTPBase(verify=False, ca_bundle=None)
    security = security_context(sec_config)
    # Class instance that supports the metadata.Base interface
    MetadataFunc = MetaDataMDX(sha1_entity_transform, ONTS.values(), ATTRCONV, args.mdx,
                               security, None, http, node_name="{}:{}".format(md.EntityDescriptor.c_namespace,
                                                                              md.EntitiesDescriptor.c_tag))
    ClientDB = MDQClient(args.cdb)

    base_url = args.base
    if not base_url.endswith("/"):
        base_url += "/"

    OP = InAcademiaOIDCProvider(base_url, ClientDB)
    SP = InAcademiaSAMLServiceProvider(base_url, MetadataFunc, args.disco_url, args.idp_entity_id)
    inacademia = InAcademiaServer(base_url, OP, SP, ClientDB, MetadataFunc)


    # ============== Web server ===============
    cherrypy.config.update({
        # "request.error_response": _send_418,

        "tools.I18nTool.on": True,
        "tools.I18nTool.default": "en",
        "tools.I18nTool.mo_dir": pkg_resources.resource_filename("svs", "data/i18n/locales"),
        "tools.I18nTool.domain": "messages",

        "log.access_file": "svs_access.log",
        "log.error_file": "svs_error.log",
    })

    cherrypy.config.update({'engine.autoreload_on': False})

    cherrypy.server.socket_host = args.host
    cherrypy.server.socket_port = args.port

    cherrypy.tree.mount(inacademia, "/", config={
        "/static": {
            "tools.staticdir.on": True,
            "tools.staticdir.dir": os.path.join(os.getcwd(), "static"),
        },
        "/robots.txt": {
            "tools.staticfile.on": True,
            "tools.staticfile.filename": pkg_resources.resource_filename("svs", "site/static/robots.txt"),
        },
        "/webroot": {
            "tools.staticdir.on": True,
            "tools.staticdir.dir": pkg_resources.resource_filename("svs", "site/static/")
        }
    })
    cherrypy.tree.mount(WellKnownHandler(inacademia), "/.well-known")
    cherrypy.tree.mount(AssertionConsumerServiceHandler(inacademia), "/acs")
    cherrypy.tree.mount(ConsentHandler(inacademia), "/consent")
    print("SvS core listening on %s:%s" % (args.host, args.port))

    # Enable CherryPy's signal handling
    if hasattr(cherrypy.engine, 'signal_handler'):
        cherrypy.engine.signal_handler.subscribe()

    cherrypy.engine.start()
    cherrypy.engine.block()


def _error(redirect_uri, err, descr=None):
    """
    Construct an error response.

    :param err: OpenID Connect error code
    :param descr: error message string
    :return: raises cherrypy.HTTPRedirect to send the error to the RP.
    """
    error_resp = AuthorizationErrorResponse(error=err, error_description=descr)
    location = error_resp.request(redirect_uri, True)
    raise cherrypy.HTTPRedirect(location)


def _response_to_cherrypy(response):
    """
    Convert between internal response and CherryPy response.

    :param response: response to return
    :return: response content if the response is not a redirect, in which case a cherrypy.HTTPRedirect will be raised
    instead.
    """
    if isinstance(response, Redirect):
        raise cherrypy.HTTPRedirect(response.message, 302)
    elif isinstance(response, SeeOther):
        raise cherrypy.HTTPRedirect(response.message, 303)
    else:
        cherrypy.response.headers.update(dict(response.headers))
        return response.response(response.message)


def _send_418():
    """
    Set the response status to 418 ("I'm a teapot").
    """
    cherrypy.response.status = 418
    cherrypy.response.body = ''


class InAcademiaServer(object):
    """
    The main CherryPy application, with all exposed endpoints.
    """

    def __init__(self, base_url, op, sp, client_metadata_func, idp_metadata_func):
        self.base_url = base_url
        self.op = op
        self.sp = sp
        self.client_metadata_func = client_metadata_func
        self.idp_metadata_func = idp_metadata_func

        # Setup key for encrypting/decrypting the state (passed in the SAML RelayState).
        source = "file://symkey.json"
        self.key_bundle = KeyBundle(source=source, fileformat="jwk")

        for key in self.key_bundle.keys():
            key.deserialize()

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect("http://www.inacademia.org")

    @cherrypy.expose
    def status(self):
        return

    @cherrypy.expose
    def authorization(self, *args, **kwargs):
        """
        Where the OP Authentication Request arrives
        """

        session = self.op.verify_authn_request(cherrypy.request.query_string)
        state = self.encode_state(session)

        log_transaction_start(logger, cherrypy.request, state, session["client_id"], session["scope"],
                              session["redirect_uri"])
        return self.sp.redirect_to_auth(state, session["scope"])


    @cherrypy.expose
    def disco(self, state=None, entityID=None, **kwargs):
        """
        Where the SAML Discovery Service response arrives.
        """
        # TODO handle "error in kwargs" - show error page or notify RP

        if state is None or entityID is None:
            raise cherrypy.HTTPError(404, _('Page not found.'))

        decoded_state = self.decode_state(state)
        return self.sp.disco(entityID, state, decoded_state)

    @cherrypy.expose
    def error(self, lang=None, error=None):
        if error is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        self.set_language(lang)

        error = json.loads(urllib.unquote_plus(error))
        error["message"] = _(error["error_key"])  # Translate the error message
        raise EndUserErrorResponse(**error)

    def set_language(self, lang):
        if lang is None:
            lang = "en"

        # Modify the Accept-Language header and use the CherryPy i18n tool for translation
        cherrypy.request.headers["Accept-Language"] = lang
        i18n_args = {
            "default": cherrypy.config["tools.I18nTool.default"],
            "mo_dir": cherrypy.config["tools.I18nTool.mo_dir"],
            "domain": cherrypy.config["tools.I18nTool.domain"]
        }
        cherrypy.tools.I18nTool.callable(**i18n_args)

    def decode_state(self, state):
        try:
            # Verify the state encryption
            return deconstruct_state(state, self.key_bundle.keys())
        except DecryptionFailed as e:
            t = now()
            uid = get_new_error_uid()
            _log_msg = "Transaction state missing or broken in incoming response."
            log_transaction_fail(logger, cherrypy.request, "-", _log_msg, timestamp=t, uid=uid)
            raise EndUserErrorResponse(t, uid, "error_general", _("error_general"))

    def encode_state(self, payload):
        _kids = self.key_bundle.kids()
        _kids.sort()
        # default alg="A128KW", enc="A128CBC-HS256"

        return construct_state(payload, self.key_bundle.get_key_with_kid(_kids[-1]))

    def make_consent_page(self, rp_client_id, idp_entity_id, released_attributes, relay_state):
        question = _("consent_question").format(rp_display_name=self._get_RP_display_name(rp_client_id))

        state = {
            "idp_entity_id": idp_entity_id,
            "state": relay_state,
        }

        return LOOKUP.get_template("consent.mako").render(consent_question=question,
                                                          released_attributes=released_attributes,
                                                          state=state,
                                                          form_action="{}consent".format(self.base_url),
                                                          language=cherrypy.response.i18n.locale.language)

    def _get_RP_display_name(self, client_id):
        # TODO get the real display name from metadata: return self.client_metadata_func[client_id]["display_name"]
        return client_id


class InAcademiaOIDCProvider(object):
    """
    The OpenID Connect Provider part of InAcademia.
    """

    def __init__(self, base_url, client_metadata_func):
        # Read OP configuration from file
        with open("conf/op_config.json", "r") as f:
            op_capabilities = json.load(f)
        for key, value in op_capabilities.iteritems():
            if isinstance(value, basestring):
                op_capabilities[key] = value.format(base=base_url)  # replace placeholder with the actual base name

        self.OP = Provider(base_url, {}, client_metadata_func, None, None, None, None, None,
                           capabilities=op_capabilities)
        self.OP.baseurl = op_capabilities["issuer"]

        # Setup up keys for signing and encrypting
        self.OP.keyjar = KeyJar()
        kbl = []
        kb = keybundle_from_local_file("inAcademia", "RSA", ["sig", "enc"])
        self.OP.keyjar.add_kb("", kb)
        kbl.append(kb)

        try:
            new_name = "static/jwks.json"
            dump_jwks(kbl, new_name)
            self.OP.jwks_uri.append("%s%s" % (base_url, new_name))
        except Exception as e:
            logger.error("Signing and encryption keys could not be written to jwks.json: '{}'".format(e))

    def providerinfo(self):
        return _response_to_cherrypy(self.OP.providerinfo_endpoint())

    def webfinger(self, resource):
        wf = WebFinger()
        return wf.response(subject=resource, base=self.OP.baseurl)

    def id_token(self, released_attributes, idp_entity_id, encoded_state, decoded_state):
        """
        Make a JWT encoded id token and pass it to the redirect URI.

        :param released_attributes: dictionary containing the following
            user_id: identifier for the user (as delivered by the IdP, dependent on whether transient or persistent
                        id was requested)
            auth_time: time of the authentication reported from the IdP
            idp_entity_id: entity id of the selected IdP
        :param encoded_state:
        :return: raises cherrypy.HTTPRedirect.
        """

        identifier = released_attributes["identifier"]
        auth_time = released_attributes["authentication time"]

        # have to convert text representation into seconds since epoch
        _time = time.mktime(str_to_time(auth_time))

        # construct the OIDC response
        session = decoded_state
        session["sub"] = identifier

        extra_claims = {k: released_attributes[k] for k in ["country", "domain"] if k in released_attributes}
        _jwt = self.OP.id_token_as_signed_jwt(session, loa="", auth_time=_time, exp={"minutes": 30},
                                              extra_claims=extra_claims)

        _elapsed_transaction_time = get_timestamp() - session["start_time"]
        log_transaction_success(logger, cherrypy.request, encoded_state, session["client_id"], idp_entity_id,
                                _time, extra_claims, _jwt, _elapsed_transaction_time)

        try:
            _state = session["state"]
        except KeyError:
            _state = None
        authzresp = AuthorizationResponse(state=_state,
                                          scope=session["scope"],
                                          id_token=_jwt)

        if "redirect_uri" in session:
            _ruri = session["redirect_uri"]
        else:
            try:
                cinfo = self.OP.cdb[session["client_id"]]
                _ruri = cinfo["redirect_uris"][0]
            except NoClientInfoReceivedError as e:
                t = now()
                uid = get_new_error_uid()
                _log_msg = "Unknown RP client id '{}': '{}'.".format(session["client_id"], str(e))
                log_transaction_fail(logger, cherrypy.request, "-", _log_msg, timestamp=t, uid=uid)
                raise EndUserErrorResponse(t, uid, "error_general", _("error_general"))

        location = authzresp.request(_ruri, True)
        logger.debug("Redirected to: '%s' (%s)" % (location, type(location)))
        raise cherrypy.HTTPRedirect(location)

    def _verify_scope(self, scope):
        """
        Verifies the scope received from the RP.

        Only one affiliation request is allowed to be specified, and if 'persistent' is specified 'transient'
        is not allowed.

        :param scope: requested scope from the RP
        :return: True if the values in scope are valid, otherwise False.
        """

        requested_affiliations = [a for a in AFFILIATIONS if a in scope]
        if len(requested_affiliations) != 1:
            return False

        if PERSISTENT_NAMEID in scope:
            return TRANSIENT_NAMEID not in scope

        return True

    def verify_authn_request(self, query_string):
        """
        Verify the incoming authentication request from the RP.

        :param query_string: query string in the request
        :param key_bundle: keys for encrypting the transaction state
        :return: tuple containing the encoded state and the scope requested by the RP.
        """
        try:
            areq = self.OP.server.parse_authorization_request(query=query_string)
        except MissingRequiredAttribute as err:
            log_internal(logger, str(err), cherrypy.request)
            # _error("invalid_request", "%s" % err)
        except KeyError:
            areq = AuthorizationRequest().deserialize(query_string, "urlencoded")
        except Exception as err:
            _log_msg = "The authentication request could not be processed: {}".format(str(err))
            log_transaction_aborted(logger, cherrypy.request, _log_msg)
            # _error("invalid_request", "The authentication request could not be processed")

        client_id = areq["client_id"]
        scope = areq["scope"]

        # Verify that the response_type if present is id_token
        try:
            assert areq["response_type"] == ["id_token"]
        except (KeyError, AssertionError) as err:  # has to be there and match
            _log_msg = "Unsupported response_type '{}'".format(areq["response_type"])
            log_transaction_aborted(logger, cherrypy.request, _log_msg, client_id)
            # _error("unsupported_response_type", "Unsupported response_type, must be id_token")

        # Verify it's a client_id I recognize
        try:
            cinfo = self.OP.cdb[client_id]
        except NoClientInfoReceivedError as e:
            t = now()
            uid = get_new_error_uid()
            _log_msg = "Unknown RP client id '{}': '{}'.".format(client_id, str(e))
            log_transaction_fail(logger, cherrypy.request, "-", _log_msg, timestamp=t, uid=uid)
            raise EndUserErrorResponse(t, uid, "error_general", _("error_general"))

        if not self._verify_scope(scope):
            _log_msg = "Invalid scope '{}'".format(scope)
            log_transaction_aborted(logger, cherrypy.request, _log_msg, client_id)
            # _error("invalid_scope", "Invalid scope")

        # verify that the redirect_uri is sound
        if "redirect_uri" not in areq:
            _log_msg = "Missing redirect URI."
            log_transaction_aborted(logger, cherrypy.request, _log_msg, client_id)
            # _error("invalid_request", "Missing redirect URI")
        elif areq["redirect_uri"] not in cinfo["redirect_uris"]:
            _log_msg = "Unknown redirect URI '{}' not in '{}'".format(areq["redirect_uri"], cinfo["redirect_uris"])
            log_transaction_aborted(logger, cherrypy.request, _log_msg, client_id)
            # _error("invalid_request", "Unknown redirect URI")

        # Create the state variable
        session = {
            "client_id": client_id,
            "nonce": areq["nonce"],
            "scope": scope,
            "redirect_uri": areq["redirect_uri"],
            "start_time": get_timestamp()
        }

        if "state" in areq:
            session["state"] = areq["state"]

        return session


class InAcademiaSAMLServiceProvider(object):
    """
    The SAML Service Provider part of InAcademia.
    """

    def __init__(self, base_url, idp_metadata_func, disco_url, idp_entity_id):
        self.idp_entity_id = idp_entity_id

        self.SP = {}
        sp_configs = make_metadata(base_url)
        for sp_key in [TRANSIENT_SP_KEY, PERSISTENT_SP_KEY]:
            cnf = SPConfig().load(sp_configs[sp_key])
            self.SP[sp_key] = SamlSp(None, cnf, idp_metadata_func, disco_url)

    def redirect_to_auth(self, state, scope):
        """
        Redirect to the discovery server or send a authentication directly to the configured IdP.
        :param state:
        :param scope:
        :return:
        """
        sp = self._choose_service_provider(scope)

        if sp.disco_srv is not None:
            location = sp.disco_query(state)
            raise cherrypy.HTTPRedirect(location, 303)
        else:  # go direct to the IdP
            entity_id = self.idp_entity_id
            resp = sp.redirect_to_auth(entity_id, state)

        return _response_to_cherrypy(resp)


    def _choose_service_provider(self, scope):
        """
        Choose the correct SP to communicate with the IdP based on the requested (and allowed) scope from the RP.
        :param SP: dict of SP's with different attribute release policies and persistent or transient name id
        :param scope: requested scope from the RP
        :return: the SP object to use when creating/sending the authentication request to the IdP.
        """

        if PERSISTENT_NAMEID in scope:
            sp_key = PERSISTENT_SP_KEY
        else:
            sp_key = TRANSIENT_SP_KEY

        return self.SP[sp_key]

    def disco(self, entityID, encoded_state, decoded_state):
        sp = self._choose_service_provider(decoded_state["scope"])
        if entityID == "":  # none was chosen return an error message
            log_transaction_fail(logger, cherrypy.request, encoded_state,
                                 "No IdP entity id returned from the discovery server.", decoded_state["client_id"])
            raise EndUserErrorResponse(0, 0, "error_general", _("error_general"))

        # check if the IdP is part of edugain
        parsed = urlparse.urlparse(entityID)
        pqs = urlparse.parse_qs(parsed.query)

        # Re-assemble the entity id without query string and fragment identifier
        idp_entity_id = urlparse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", ""))
        try:
            if pqs["inedugain"][0] == "false":
                t = now()
                uid = get_new_error_uid()
                _log_msg = "Non-edugain IdP '{}' returned from discovery server".format(idp_entity_id)
                log_transaction_fail(logger, cherrypy.request, encoded_state, _log_msg, decoded_state["client_id"], t,
                                     uid)
                raise EndUserErrorResponse(t, uid, "error_non_edugain_idp", _("error_non_edugain_idp"),
                                           _("solution_contact_idp"))
        except KeyError:
            pass

        log_transaction_idp(logger, cherrypy.request, encoded_state, decoded_state["client_id"], idp_entity_id)

        # Construct the SAML2 AuthenticationRequest and send it
        try:
            return _response_to_cherrypy(sp.redirect_to_auth(idp_entity_id, encoded_state))
        except ServiceErrorException as e:
            log_transaction_fail(logger, cherrypy.request, encoded_state, str(e), decoded_state["client_id"])
            raise EndUserErrorResponse(0, 0, "error_idp_error", _("error_idp_error"))

    def acs(self, SAMLResponse, binding, encoded_state, decoded_state):
        """
        Handle the SAML Authentication Request (received at the SP's assertion consumer URL).
        :return:
        """
        scope = decoded_state["scope"]
        sp = self._choose_service_provider(scope)
        try:
            name_id, identity, auth_time, idp_entity_id = sp.parse_auth_response(SAMLResponse, binding)
            log_internal(logger, "saml_response name_id={}".format(str(name_id).replace("\n", "")),
                         environ=cherrypy.request, transaction_id=encoded_state, client_id=decoded_state["client_id"])
        except AuthnFailure:
            log_transaction_fail(logger, cherrypy.request, encoded_state, "User not authenticated at IdP",
                                 decoded_state["client_id"])
            raise EndUserErrorResponse(0, 0, "error_user_not_authenticated", _("error_user_not_authenticated"),
                                       _("solution_contact_idp"))
        except Exception as e:
            _log_msg = "Incorrect SAML Response from IdP: '{}'".format(str(e))
            log_transaction_fail(logger, cherrypy.request, encoded_state, _log_msg, decoded_state["client_id"])
            raise EndUserErrorResponse(0, 0, "error_incorrect_saml_response", _("error_incorrect_saml_response"))

        has_correct_affiliation = get_affiliation_function(scope)

        if not has_correct_affiliation(identity):
            return _error(decoded_state["redirect_uri"], "access_denied",
                          "The user does not have the correct affiliation.")

        _user_id = get_name_id(name_id, identity, scope)
        if _user_id is None:
            return _error(decoded_state["redirect_uri"], "access_denied",
                          "The users identity could not be provided.")

        return _user_id, identity, auth_time, idp_entity_id


class ConsentHandler(object):
    def __init__(self, server):
        self.server = server

    @cherrypy.expose
    def ok(self, state=None, released_attributes=None):
        if state is None or released_attributes is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        state = json.loads(urllib.unquote_plus(state))
        released_attributes = json.loads(urllib.unquote_plus(released_attributes))
        decoded_state = self.server.decode_state(state["state"])
        return self.server.op.id_token(released_attributes, state["idp_entity_id"], state["state"], decoded_state)

    @cherrypy.expose
    def fail(self, state=None):
        if state is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        state = json.loads(urllib.unquote_plus(state))
        decoded_state = self.server.decode_state(state["state"])
        log_transaction_fail(logger, cherrypy.request, state["state"], "No consent given by user.",
                             decoded_state["client_id"])
        _error(decoded_state["redirect_uri"], "access_denied", "User did not give consent.")

    @cherrypy.expose
    def index(self, lang=None, state=None, released_attributes=None):
        if state is None or released_attributes is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        self.server.set_language(lang)

        state = json.loads(urllib.unquote_plus(state))
        rp_client_id = self.server.decode_state(state["state"])["client_id"]
        released_attributes = json.loads(urllib.unquote_plus(released_attributes))

        return self.server.make_consent_page(rp_client_id, state["idp_entity_id"], released_attributes, state["state"])


class AssertionConsumerServiceHandler(object):
    def __init__(self, server):
        self.server = server

    @cherrypy.expose
    def post(self, SAMLResponse=None, RelayState=None, **kwargs):  # TODO handle RELAY_STATE named variable
        """
        Where the SAML Authentication Request Response arrives.
        """
        return self._acs(SAMLResponse, RelayState, BINDING_HTTP_POST)

    @cherrypy.expose
    def redirect(self, SAMLResponse=None, RelayState=None):
        """
        Where the SAML Authentication Request Response arrives.
        """

        return self._acs(SAMLResponse, RelayState, BINDING_HTTP_REDIRECT)

    def _acs(self, SAMLResponse, relay_state, binding):
        """
        Assertion consumer service endpoint (where the SAML authentication response is handled).
        """

        decoded_state = self.server.decode_state(relay_state)
        user_id, identity, auth_time, idp_entity_id = self.server.sp.acs(SAMLResponse, binding, relay_state,
                                                                         decoded_state)

        # if we have passed all checks, ask the user for consent before finalizing
        released_attributes = self._get_attributes_to_release(user_id, identity, auth_time, idp_entity_id,
                                                              decoded_state)

        return self.server.make_consent_page(decoded_state["client_id"], idp_entity_id, released_attributes,
                                             relay_state)

    def _generate_subject_id(self, client_id, user_id, idp_entity_id):
        """

        :param client_id:
        :param user_id:
        :param idp_entity_id:
        :return:
        """
        return hashlib.sha512(client_id + user_id + idp_entity_id).hexdigest()

    def _get_extra_attributes(self, identity, idp_entity_id, client_id, scope):
        """
        Create extra claims requested by the RP, if they are allowed to be returned to the RP and we got them from the IdP.
        :param identity: data from the IdP about the user
        :param idp_entity_id: entity id for the IdP
        :param client_id: the RP's client id
        :param scope: requested scope from the RP
        :param metadata_func: function to fetch the IdP's metadata (used to get the IdP's country)
        :return: a list of tuples with any extra claims to return to the RP with the id token.
        """

        # TODO where get this policy from?
        allowed = {client_id: [COUNTRY, DOMAIN]}

        claims = []
        if DOMAIN in allowed[client_id] and DOMAIN in scope:
            if "schacHomeOrganization" in identity:
                claims.append((N_("domain"), identity["schacHomeOrganization"][0]))

        if COUNTRY in allowed[client_id] and COUNTRY in scope:
            country = self._get_idp_country(idp_entity_id, self.server.idp_metadata_func)
            if country is not None:
                claims.append((N_("country"), country))

        return claims

    def _get_idp_country(self, entity_id, metadata_func):
        """
        Return the country of the IdP.
        :param entity_id: entity id of the IdP
        :param metadata_func: function fetching the idp metadata
        :return:
        """
        idp_info = metadata_func.service(entity_id, "idpsso_descriptor", "single_sign_on_service",
                                         BINDING_HTTP_REDIRECT)[0]

        try:
            return idp_info["country"]
        except KeyError:
            return None

    def _get_attributes_to_release(self, user_id, identity, auth_time, idp_entity_id, state):
        attributes = [N_("affiliation"), N_("identifier"), N_("authentication time")]
        values = [identity[AFFILIATION_ATTRIBUTE],
                  self._generate_subject_id(state["client_id"], user_id, idp_entity_id),
                  auth_time]
        l = zip(attributes, values)

        extra_attributes = self._get_extra_attributes(identity, idp_entity_id, state["client_id"], state["scope"])
        l.extend(extra_attributes)

        return dict(l)


class WellKnownHandler(object):
    def __init__(self, server):
        self.server = server


    @cherrypy.expose
    def openid_configuration(self):
        """
        Where the OP configuration request (directed to /.well-known/openid-configuration) arrives.
        """

        return self.server.op.providerinfo()

    @cherrypy.expose
    def webfinger(self, rel=None, resource=None):
        """
        Where the WebFinger request arrives.
        """

        # Verify that all required parameters are present
        try:
            assert rel == [OIC_ISSUER]
            assert resource is not None
        except AssertionError as e:
            raise cherrypy.HTTPError(400, "Missing parameter in request")

        return self.server.op.webfinger(cherrypy.request)


if __name__ == '__main__':
    main()