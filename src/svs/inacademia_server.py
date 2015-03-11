import json
import logging.config
import os
import urllib

import cherrypy
from oic.utils.clientdb import MDQClient
from oic.utils.keyio import KeyBundle
from oic.utils.webfinger import WebFinger, OIC_ISSUER
from saml2.response import DecryptionFailed
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

from svs.cherrypy_util import PathDispatcher, response_to_cherrypy
from svs.message_utils import abort_with_client_error, abort_with_enduser_error, negative_transaction_response
from svs.oidc import InAcademiaOpenIDConnectFrontend
from svs.saml import InAcademiaSAMLBackend
from svs.user_interaction import ConsentPage, EndUserErrorResponse
from svs.i18n_tool import ugettext as _
from svs.log_utils import log_transaction_start
from svs.utils import deconstruct_state, construct_state


logger = logging.getLogger(__name__)


def setup_logging(config_dict=None, env_key="LOG_CFG", config_file="conf/logging_conf.json", level=logging.INFO):
    """Setup logging configuration.

    The configuration is fetched in order from:
        1. Supplied configuration dictionary
        2. Configuration file specified in environment variable 'LOG_CFG'
        3. Configuration file specified as parameter
        4. Basic config, configured with log level 'INFO'
    """
    if config_dict is not None:
        logging.config.dictConfig(config_dict)
    else:
        env_conf = os.getenv(env_key, None)
        if env_conf:
            config_file = env_conf

        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
            logging.config.dictConfig(config)
        else:
            logging.basicConfig(level=level)


def main():
    import argparse
    import pkg_resources

    parser = argparse.ArgumentParser()
    parser.add_argument("--mdx", dest="mdx", required=True, type=str, help="base url to the MDX server")
    parser.add_argument("--cdb", dest="cdb", required=True, type=str, help="base url to the client database server")
    parser.add_argument("--disco", dest="disco_url", type=str, help="base url to the discovery server")
    parser.add_argument("-b", dest="base", required=True, type=str, help="base url for the service")
    parser.add_argument("-H", dest="host", default="0.0.0.0", type=str, help="host for the service")
    parser.add_argument("-p", dest="port", default=8087, type=int, help="port for the service to listen on")

    args = parser.parse_args()

    # Force base url to end with '/'
    base_url = args.base
    if not base_url.endswith("/"):
        base_url += "/"

    setup_logging()

    # add directory to PATH environment variable to find xmlsec
    os.environ["PATH"] += os.pathsep + '/usr/local/bin'

    # ============== SAML ===============
    SP = InAcademiaSAMLBackend(base_url, args.mdx, args.disco_url)

    # ============== OIDC ===============
    ClientDB = MDQClient(args.cdb)
    OP = InAcademiaOpenIDConnectFrontend(base_url, ClientDB)

    # ============== Web server ===============
    inacademia = InAcademiaMediator(base_url, OP, SP)

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
    cherrypy.tree.mount(None, "/.well-known", config={
        "/": {
            "request.dispatch": PathDispatcher({
                "/webfinger": inacademia.webfinger,
                "/openid-configuration": inacademia.openid_configuration,
            })
        }
    })
    cherrypy.tree.mount(None, "/acs", config={
        "/": {
            "request.dispatch": PathDispatcher({
                "/post": inacademia.acs_post,
                "/redirect": inacademia.acs_redirect,
            })
        }
    })
    cherrypy.tree.mount(None, "/consent", config={
        "/": {
            "request.dispatch": PathDispatcher({
                "/": inacademia.consent_index,
                "/allow": inacademia.consent_allow,
                "/deny": inacademia.consent_deny
            })
        }
    })
    print("SvS core listening on {}:{}".format(args.host, args.port))

    cherrypy.engine.signal_handler.subscribe()
    cherrypy.engine.start()
    cherrypy.engine.block()


class InAcademiaMediator(object):
    """The main CherryPy application, with all exposed endpoints.

    This app mediates between a OpenIDConnect provider front-end, which uses SAML as the back-end for authenticating
    users.
    """

    def __init__(self, base_url, op, sp):
        self.base_url = base_url
        self.op = op
        self.sp = sp

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
        """Where the OP Authentication Request arrives.
        """
        transaction_session = self.op.verify_authn_request(cherrypy.request.query_string)
        state = self._encode_state(transaction_session)

        log_transaction_start(logger, cherrypy.request, state, transaction_session["client_id"],
                              transaction_session["scope"],
                              transaction_session["redirect_uri"])
        return self.sp.redirect_to_auth(state, transaction_session["scope"])


    @cherrypy.expose
    def disco(self, state=None, entityID=None, **kwargs):
        """Where the SAML Discovery Service response arrives.
        """
        if state is None:
            raise cherrypy.HTTPError(404, _('Page not found.'))

        transaction_session = self._decode_state(state)
        if "error" in kwargs:
            abort_with_client_error(state, transaction_session, cherrypy.request, logger,
                                    "Discovery service error: '{}'.".format(kwargs["error"]))
        elif entityID is None or entityID == "":
            abort_with_client_error(state, transaction_session, cherrypy.request, logger,
                                    "No entity id returned from discovery server.")

        return self.sp.disco(entityID, state, transaction_session)

    @cherrypy.expose
    def error(self, lang=None, error=None):
        """Where the i18n of the error page is handled.
        """
        if error is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        self._set_language(lang)

        error = json.loads(urllib.unquote_plus(error))
        raise EndUserErrorResponse(**error)

    def webfinger(self, rel=None, resource=None):
        """Where the WebFinger request arrives.

        This function is mapped explicitly using PathDiscpatcher.
        """

        try:
            assert rel == OIC_ISSUER
            assert resource is not None
        except AssertionError as e:
            raise cherrypy.HTTPError(400, "Missing or incorrect parameter in webfinger request.")

        cherrypy.response.headers["Content-Type"] = "application/jrd+json"
        return WebFinger().response(resource, self.op.OP.baseurl)

    def openid_configuration(self):
        """Where the OP configuration request arrives.

        This function is mapped explicitly using PathDispatcher.
        """

        return response_to_cherrypy(self.op.OP.providerinfo_endpoint())

    def consent_allow(self, state=None, released_claims=None):
        """Where the approved consent arrives.

        This function is mapped explicitly using PathDispatcher.
        """
        if state is None or released_claims is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        state = json.loads(urllib.unquote_plus(state))
        released_claims = json.loads(urllib.unquote_plus(released_claims))
        transaction_session = self._decode_state(state["state"])
        return self.op.id_token(released_claims, state["idp_entity_id"], state["state"], transaction_session)

    def consent_deny(self, state=None):
        """Where the denied consent arrives.

        This function is mapped explicitly using PathDispatcher.
        """
        if state is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        state = json.loads(urllib.unquote_plus(state))
        transaction_session = self._decode_state(state["state"])
        negative_transaction_response(state["state"], transaction_session, cherrypy.request, logger,
                                      "User did not give consent.", state["idp_entity_id"])

    def consent_index(self, lang=None, state=None, released_claims=None):
        """Where the i18n of the consent page arrives.

        This function is mapped explicitly using PathDispatcher.
        """
        if state is None or released_claims is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        self._set_language(lang)

        state = json.loads(urllib.unquote_plus(state))
        rp_client_id = self._decode_state(state["state"])["client_id"]
        released_claims = json.loads(urllib.unquote_plus(released_claims))

        client_name = self._get_client_name(rp_client_id)
        return ConsentPage.render(client_name, state["idp_entity_id"], released_claims, state["state"])

    def acs_post(self, SAMLResponse=None, RelayState=None, **kwargs):
        """Where the SAML Authentication Response arrives.

        This function is mapped explicitly using PathDiscpatcher.
        """
        return self._acs(SAMLResponse, RelayState, BINDING_HTTP_POST)

    def acs_redirect(self, SAMLResponse=None, RelayState=None):
        """Where the SAML Authentication Response arrives.
        """

        return self._acs(SAMLResponse, RelayState, BINDING_HTTP_REDIRECT)

    def _acs(self, SAMLResponse, RelayState, binding):
        """Handle the SAMLResponse from the IdP and produce the consent page.

        :return: HTML of the OP consent page.
        """
        transaction_session = self._decode_state(RelayState)
        user_id, identity, auth_time, idp_entity_id = self.sp.acs(SAMLResponse, binding, RelayState,
                                                                  transaction_session)

        # if we have passed all checks, ask the user for consent before finalizing
        released_claims = self.op.get_claims_to_release(user_id, identity, auth_time, idp_entity_id,
                                                        self.sp.metadata, transaction_session)

        client_name = self._get_client_name(transaction_session["client_id"])
        return ConsentPage.render(client_name, idp_entity_id, released_claims, RelayState)

    def _set_language(self, lang):
        """Set the language.
        """
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

    def _decode_state(self, state):
        """Decode the transaction data.

        If the state can not be decoded, the transaction will fail with error page for the user. We can't
        notify the client since the transaction state now is unknown.
        """
        try:
            return deconstruct_state(state, self.key_bundle.keys())
        except DecryptionFailed as e:
            abort_with_enduser_error(state, "-", cherrypy.request, logger,
                                     _("We could not complete your validation because an error occurred while handling "
                                       "your request. Please return to the service which initiated the validation "
                                       "request and try again."),
                                     "Transaction state missing or broken in incoming response.")

    def _encode_state(self, payload):
        """Encode the transaction data.
        """
        _kids = self.key_bundle.kids()
        _kids.sort()

        return construct_state(payload, self.key_bundle.get_key_with_kid(_kids[-1]))

    def _get_client_name(self, client_id):
        """Get the display name for the client.

        :return: the clients display name, or client_id if no display name is known.
        """
        return self.op.OP.cdb[client_id].get("display_name", client_id)


if __name__ == '__main__':
    main()