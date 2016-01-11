import hashlib
import json
import logging
import time

import cherrypy
from oic.oic.message import AuthorizationResponse
from oic.oic.provider import Provider
from oic.utils.clientdb import NoClientInfoReceivedError
from oic.utils.keyio import KeyJar, keybundle_from_local_file, dump_jwks
from oic.utils.time_util import str_to_time
import requests

from svs.filter import AFFILIATIONS, PERSISTENT_NAMEID, TRANSIENT_NAMEID, SCOPE_VALUES, DOMAIN, COUNTRY, \
    AFFILIATION_ATTRIBUTE
from svs.utils import get_timestamp, N_
from svs.log_utils import log_transaction_complete, log_internal
from svs.message_utils import abort_with_enduser_error, abort_with_client_error
from svs.i18n_tool import ugettext as _


__author__ = 'regu0004'

logger = logging.getLogger(__name__)


class InAcademiaOpenIDConnectFrontend(object):
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
        kb = keybundle_from_local_file("inAcademia", "RSA", ["sig", "enc"])
        self.OP.keyjar.add_kb("", kb)

        try:
            file_name = "static/jwks.json"
            dump_jwks([kb], file_name)
            self.OP.jwks_uri.append("{}/{}".format(base_url, file_name))
        except Exception as e:
            logger.exception("Signing and encryption keys could not be written to jwks.json.")
            raise

    def id_token(self, released_claims, idp_entity_id, transaction_id, transaction_session):
        """Make a JWT encoded id token and pass it to the redirect URI.

        :param released_claims: dictionary containing the following
            user_id: identifier for the user (as delivered by the IdP, dependent on whether transient or persistent
                        id was requested)
            auth_time: time of the authentication reported from the IdP
            idp_entity_id: entity id of the selected IdP
        :param transaction_id:
        :return: raises cherrypy.HTTPRedirect.
        """

        identifier = released_claims["Identifier"]
        auth_time = released_claims["Authentication time"]

        # have to convert text representation into seconds since epoch
        _time = time.mktime(str_to_time(auth_time))

        # construct the OIDC response
        transaction_session["sub"] = identifier

        extra_claims = {k.lower(): released_claims[k] for k in ["Country", "Domain"] if k in released_claims}
        _jwt = self.OP.id_token_as_signed_jwt(transaction_session, loa="", auth_time=_time, exp={"minutes": 30},
                                              extra_claims=extra_claims)

        _elapsed_transaction_time = get_timestamp() - transaction_session["start_time"]
        log_transaction_complete(logger, cherrypy.request, transaction_id,
                                 transaction_session["client_id"],
                                 idp_entity_id, _time, _elapsed_transaction_time,
                                 extra_claims, _jwt)

        try:
            _state = transaction_session["state"]
        except KeyError:
            _state = None
        authzresp = AuthorizationResponse(state=_state, id_token=_jwt)

        if "redirect_uri" in transaction_session:
            _ruri = transaction_session["redirect_uri"]
        else:
            _error_msg = _("We could not complete your validation because an error occurred while "
                           "handling your request. Please return to the service which initiated the "
                           "validation request and try again.")
            try:
                cinfo = self.OP.cdb[transaction_session["client_id"]]
                _ruri = cinfo["redirect_uris"][0]
            except NoClientInfoReceivedError as e:
                abort_with_enduser_error(transaction_id, transaction_session["client_id"], cherrypy.request, logger,
                                         _error_msg,
                                         "Unknown RP client id '{}': '{}'.".format(transaction_session["client_id"],
                                                                                   str(e)))
            except requests.exceptions.RequestException as e:
                abort_with_enduser_error("-", transaction_session["client_id"], cherrypy.request, logger,
                                         _error_msg,
                                         "Failed to get client metadata from MDQ server.", exc_info=True)

        location = authzresp.request(_ruri, True)
        logger.debug("Redirected to: '{}' ({})".format(location, type(location)))
        raise cherrypy.HTTPRedirect(location)

    def _verify_scope(self, scope, client_id):
        """Verifies the scope received from the RP.

        Only one affiliation request is allowed to be specified, and if 'persistent' is specified 'transient'
        is not allowed. In addition, the requested scope is verified against the clients permissions.

        :param scope: requested scope from the RP
        :return: True if the values in scope are valid, otherwise False.
        """

        # Malformed scope requesting validation of more than one affiliation type
        requested_affiliations = [a for a in AFFILIATIONS if a in scope]
        if len(requested_affiliations) != 1:
            return False

        # Malformed scope containing both 'persistent' and 'transient'
        if PERSISTENT_NAMEID in scope and TRANSIENT_NAMEID in scope:
            return False

        # Verify the client is allowed to request this scope
        allowed = self.OP.cdb[client_id].get("allowed_scope_values", [])
        for value in scope:
            if value == "openid":  # Always allow 'openid' in scope
                continue
            elif value in SCOPE_VALUES and value not in allowed:  # A scope we understand, but client not allowed
                log_internal(logger, "Scope value '{}' not in '{}' for client.".format(value, allowed), None,
                             client_id=client_id)
                return False

        return True

    def verify_authn_request(self, query_string):
        """Verify the incoming authentication request from the RP.

        :param query_string: query string in the request
        :param key_bundle: keys for encrypting the transaction state
        :return: tuple containing the encoded state and the scope requested by the RP.
        """
        try:
            areq = self.OP.server.parse_authorization_request(query=query_string)
        except Exception as e:
            abort_with_enduser_error("-", "-", cherrypy.request, logger,
                                     _("The authentication request could not be processed. Please return to the "
                                       "service which initiated the validation request and try again."),
                                     "The authentication request '{}' could not be processed.".format(query_string),
                                     exc_info=True)

        # Verify it's a client_id I recognize
        client_id = areq["client_id"]
        _error_msg = _("Configuration error for the service.")

        try:
            cinfo = self.OP.cdb[client_id]
        except NoClientInfoReceivedError as e:
            abort_with_enduser_error("-", client_id, cherrypy.request, logger,
                                     _error_msg,
                                     "Unknown RP client id '{}': '{}'.".format(client_id, str(e)))
        except requests.exceptions.RequestException as e:
            abort_with_enduser_error("-", client_id, cherrypy.request, logger,
                                     _error_msg,
                                     "Failed to get client metadata from MDQ server.", exc_info=True)

        # verify that the redirect_uri is sound
        if "redirect_uri" not in areq:
            abort_with_enduser_error("-", client_id, cherrypy.request, logger,
                                     _error_msg,
                                     "Missing redirect URI in authentication request.")
        elif areq["redirect_uri"] not in cinfo["redirect_uris"]:
            abort_with_enduser_error("-", client_id, cherrypy.request, logger,
                                     _error_msg,
                                     "Unknown redirect URI in authentication request: '{}' not in '{}'".format(
                                         areq["redirect_uri"],
                                         cinfo["redirect_uris"]))

        # Create the state variable
        transaction_session = {
            "client_id": client_id,
            "redirect_uri": areq["redirect_uri"],
            "nonce": areq["nonce"],
            "scope": areq["scope"],
        }

        if "state" in areq:
            transaction_session["state"] = areq["state"]

        if "claims" in areq:
            transaction_session["claims"] = areq["claims"]["id_token"].to_dict()

        # Verify that the response_type if present is id_token
        try:
            assert areq["response_type"] == ["id_token"]
        except (KeyError, AssertionError) as err:  # has to be there and match
            abort_with_client_error("-", transaction_session, cherrypy.request, logger,
                                    "Unsupported response_type '{}'".format(areq["response_type"]),
                                    error="unsupported_response_type",
                                    error_description="Only response_type 'id_token' is supported.")

        if not self._verify_scope(areq["scope"], client_id):
            abort_with_client_error("-", transaction_session, cherrypy.request, logger,
                                    "Invalid scope '{}'".format(areq["scope"]),
                                    error="invalid_scope",
                                    error_description="The specified scope '{}' is not valid.".format(" ".join(areq["scope"])))

        transaction_session.update({
            "start_time": get_timestamp()
        })

        return transaction_session

    def get_claims_to_release(self, user_id, affiliation, identity, auth_time, idp_entity_id, idp_metadata_func,
                              transaction_session):
        """
        Compile a dictionary of a all claims we will release to the client.

        :param user_id: identifier for the user
        :param identity: assertions about the user from the IdP
        :param auth_time: time of authentication reported from the IdP
        :param idp_entity_id: id of the IdP
        :param idp_metadata_func: callable to fetch idp metadata
        :param transaction_session: transaction data
        :return:
        """
        attributes = [N_("Affiliation"), N_("Identifier"), N_("Authentication time")]
        values = [affiliation,
                  self._generate_subject_id(transaction_session["client_id"], user_id, idp_entity_id),
                  auth_time]
        l = zip(attributes, values)

        extra_claims = self._get_extra_claims(idp_metadata_func, identity, idp_entity_id,
                                              transaction_session.get("claims", []), transaction_session["client_id"])
        l.extend(extra_claims)

        return dict(l)

    def _get_extra_claims(self, idp_metadata_func, identity, idp_entity_id, requested_claims, client_id):
        """Create the extra claims requested by the RP.

        Extra claims will only be returned if the RP is allowed to request them and we got them from the IdP.

        :param idp_metadata_func: callable to fetch idp metadata
        :param identity: assertions from the IdP about the user
        :param idp_entity_id: entity id of the IdP
        :param requested_claims: the requested claims from the RP
        :param client_id: RP client id
        :return: a list of tuples with any extra claims to return to the RP with the id token.
        """

        # Verify the client is allowed to request these claims
        allowed = self.OP.cdb[client_id].get("allowed_claims", [])
        for value in requested_claims:
            if value not in allowed:
                log_internal(logger, "Claim '{}' not in '{}' for client.".format(value, allowed), None,
                             client_id=client_id)

        claims = []
        if DOMAIN in requested_claims and DOMAIN in allowed:
            if "schacHomeOrganization" in identity:
                claims.append((N_("Domain"), identity["schacHomeOrganization"][0]))

        if COUNTRY in requested_claims and COUNTRY in allowed:
            country = self._get_idp_country(idp_metadata_func, idp_entity_id)
            if country is not None:
                claims.append((N_("Country"), country))

        return claims

    def _generate_subject_id(self, client_id, user_id, idp_entity_id):
        """Construct the subject identifier for the ID Token.

        :param client_id: id of the client (RP)
        :param user_id: id of the end user
        :param idp_entity_id: id of the IdP
        """
        return hashlib.sha512(client_id + user_id + idp_entity_id).hexdigest()

    def _get_idp_country(self, metadata, entity_id):
        """Get the country of the IdP.

        :param metadata: function fetching the IdP metadata
        :param entity_id: entity id of the IdP
        """
        idp_info = metadata[entity_id]
        return idp_info.get("country", None)