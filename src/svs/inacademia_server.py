import hashlib
import json
import logging.config
import os
import urllib

import cherrypy
from oic.utils.clientdb import MDQClient
from oic.utils.keyio import KeyBundle
from oic.utils.webfinger import WebFinger, OIC_ISSUER
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

from svs.cherrypy_util import PathDispatcher, response_to_cherrypy
from svs.message_utils import abort_with_client_error, abort_with_enduser_error, negative_transaction_response
from svs.oidc import InAcademiaOpenIDConnectFrontend
from svs.saml import InAcademiaSAMLBackend
from svs.user_interaction import ConsentPage, EndUserErrorResponse
from svs.i18n_tool import ugettext as _
from svs.filter import COUNTRY, \
    DOMAIN, AFFILIATION_ATTRIBUTE
from svs.log_utils import log_transaction_start
from svs.utils import sha1_entity_transform, deconstruct_state, construct_state, N_


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
    parser.add_argument("--disco", dest="disco_url", type=str, help="base url to the discovery server")
    parser.add_argument("-b", dest="base", required=True, type=str, help="base url for the service")
    parser.add_argument("-H", dest="host", default="0.0.0.0", type=str, help="host for the service")
    parser.add_argument("-p", dest="port", default=8087, type=int, help="port for the service to listen on")

    args = parser.parse_args()

    # Force base url to end with '/'
    base_url = args.base
    if not base_url.endswith("/"):
        base_url += "/"

    with open("conf/logging_conf.json", "r") as f:
        logging_conf = json.load(f)
    setup_logging(config_dict=logging_conf)

    # add directory to PATH environment variable to find xmlsec
    os.environ["PATH"] += os.pathsep + '/usr/local/bin'

    # ============== SAML ===============
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
    MetadataFunc = MetaDataMDX(sha1_entity_transform, ONTS.values(), ATTRCONV, args.mdx,
                               security, None, http, node_name="{}:{}".format(md.EntityDescriptor.c_namespace,
                                                                              md.EntitiesDescriptor.c_tag))
    SP = InAcademiaSAMLBackend(base_url, MetadataFunc, args.disco_url)

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
                "/ok": inacademia.consent_ok,
                "/fail": inacademia.consent_ok
            })
        }
    })
    print("SvS core listening on %s:%s" % (args.host, args.port))

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
        session = self.op.verify_authn_request(cherrypy.request.query_string)
        state = self._encode_state(session)

        log_transaction_start(logger, cherrypy.request, state, session["client_id"], session["scope"],
                              session["redirect_uri"])
        return self.sp.redirect_to_auth(state, session["scope"])


    @cherrypy.expose
    def disco(self, state=None, entityID=None, **kwargs):
        """Where the SAML Discovery Service response arrives.
        """
        if state is None:
            raise cherrypy.HTTPError(404, _('Page not found.'))

        session = self._decode_state(state)
        if "error" in kwargs:
            abort_with_client_error(state, session, logger, "Discovery service error: '{}'.".format(kwargs["error"]))
        elif entityID is None or entityID == "":
            abort_with_client_error(state, session, logger, "No entity id returned from discovery server.")

        return self.sp.disco(entityID, state, session)

    @cherrypy.expose
    def error(self, lang=None, error=None):
        """Where the i18n of the error page is handled.
        """
        if error is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        self._set_language(lang)

        error = json.loads(urllib.unquote_plus(error))
        error["message"] = _(error["error_key"])  # Re-translate the error message
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

        This function is mapped explicitly using PathDiscpatcher.
        """

        return response_to_cherrypy(self.op.OP.providerinfo_endpoint())

    def consent_ok(self, state=None, released_attributes=None):
        """Where the approved consent arrives.

        This function is mapped explicitly using PathDiscpatcher.
        """
        if state is None or released_attributes is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        state = json.loads(urllib.unquote_plus(state))
        released_attributes = json.loads(urllib.unquote_plus(released_attributes))
        decoded_state = self._decode_state(state["state"])
        return self.op.id_token(released_attributes, state["idp_entity_id"], state["state"], decoded_state)

    def consent_fail(self, state=None):
        """Where the denied consent arrives.

        This function is mapped explicitly using PathDiscpatcher.
        """
        if state is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        state = json.loads(urllib.unquote_plus(state))
        decoded_state = self._decode_state(state["state"])
        negative_transaction_response(state["state"], decoded_state, "User did not give consent.",
                                      state["idp_entity_id"])

    def consent_index(self, lang=None, state=None, released_attributes=None):
        """Where the i18n of the consent page arrives.

        This function is mapped explicitly using PathDiscpatcher.
        """
        if state is None or released_attributes is None:
            raise cherrypy.HTTPError(404, _("Page not found."))

        self._set_language(lang)

        state = json.loads(urllib.unquote_plus(state))
        rp_client_id = self._decode_state(state["state"])["client_id"]
        released_attributes = json.loads(urllib.unquote_plus(released_attributes))

        display_name = self._get_client_display_name(rp_client_id)
        return ConsentPage.render(self.op.OP.baseurl, display_name, state["idp_entity_id"], released_attributes,
                                  state["state"])

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
        decoded_state = self._decode_state(RelayState)
        user_id, identity, auth_time, idp_entity_id = self.sp.acs(SAMLResponse, binding, RelayState,
                                                                  decoded_state)

        # if we have passed all checks, ask the user for consent before finalizing
        released_attributes = self._get_attributes_to_release(user_id, identity, auth_time, idp_entity_id,
                                                              decoded_state)

        display_name = self._get_client_display_name(decoded_state["client_id"])
        return ConsentPage.render(self.op.OP.baseurl, display_name, idp_entity_id, released_attributes,
                                  RelayState)

    def _generate_subject_id(self, client_id, user_id, idp_entity_id):
        """Construct the subject identifier for the ID Token.

        :param client_id: id of the client (RP)
        :param user_id: id of the end user
        :param idp_entity_id: id of the IdP
        """
        return hashlib.sha512(client_id + user_id + idp_entity_id).hexdigest()

    def _get_extra_attributes(self, identity, idp_entity_id, client_id, scope):
        """Create the extra attributes (claims) requested by the RP.

        Extra attributes will only be returned if the RP is allowed to request them and we got them from the IdP.

        :param identity: assertions from the IdP about the user
        :param idp_entity_id: entity id of the IdP
        :param client_id: the RP's client id
        :param scope: requested scope from the RP
        :return: a list of tuples with any extra claims to return to the RP with the id token.
        """

        claims = []
        if DOMAIN in scope:
            if "schacHomeOrganization" in identity:
                claims.append((N_("domain"), identity["schacHomeOrganization"][0]))

        if COUNTRY in scope:
            country = self._get_idp_country(self.sp.metadata, idp_entity_id)
            if country is not None:
                claims.append((N_("country"), country))

        return claims

    def _get_idp_country(self, metadata, entity_id):
        """Get the country of the IdP.

        :param metadata: function fetching the IdP metadata
        :param entity_id: entity id of the IdP
        """
        idp_info = metadata[entity_id]
        return idp_info.get("country", None)  # TODO add country information to SAML entity metadata

    def _get_attributes_to_release(self, user_id, identity, auth_time, idp_entity_id, session):
        """
        Compile a dictionary of a all attributes (claims) we will release to the client.

        :param user_id: identifier for the user
        :param identity: assertions about the user from the IdP
        :param auth_time: time of authentication reported from the IdP
        :param idp_entity_id: id of the IdP
        :param session: transaction data
        :return:
        """
        attributes = [N_("affiliation"), N_("identifier"), N_("authentication time")]
        values = [identity[AFFILIATION_ATTRIBUTE],
                  self._generate_subject_id(session["client_id"], user_id, idp_entity_id),
                  auth_time]
        l = zip(attributes, values)

        extra_attributes = self._get_extra_attributes(identity, idp_entity_id, session["client_id"], session["scope"])
        l.extend(extra_attributes)

        return dict(l)

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
            abort_with_enduser_error(state, "-", logger, "Transaction state missing or broken in incoming response.")

    def _encode_state(self, payload):
        """Encode the transaction data.
        """
        _kids = self.key_bundle.kids()
        _kids.sort()

        return construct_state(payload, self.key_bundle.get_key_with_kid(_kids[-1]))

    def _get_client_display_name(self, client_id):
        """Get the display name for the client.

        :return: the clients display name, or client_id if no display name is known.
        """
        return self.op.OP.cdb[client_id].get("display_name", client_id)


if __name__ == '__main__':
    main()