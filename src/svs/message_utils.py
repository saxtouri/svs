import cherrypy
from oic.oic.message import AuthorizationErrorResponse

from svs.user_interaction import EndUserErrorResponse
from svs.log_utils import log_transaction_fail, \
    log_negative_transaction_complete
from svs.utils import now, get_new_error_uid, get_timestamp


__author__ = 'regu0004'


def abort_with_enduser_error(transaction_id, client_id, environ, logger,
                             error_message, log_msg, **kwargs):
    """Construct and show error page for the user.
    """
    t, uid = _log_fail(logger, log_msg, transaction_id, client_id, environ,
                       **kwargs)
    raise EndUserErrorResponse(t, uid, log_msg)


def abort_with_client_error(transaction_id, transaction_session, environ,
                            logger, log_msg, error="access_denied",
                            error_description="", **kwargs):
    """Log error and send error message.

    :param error: OpenID Connect error code
    :param error_description: error message string
    :return: raises cherrypy.HTTPRedirect to send the error to the RP.
    """
    _log_fail(logger, log_msg, transaction_id, transaction_session["client_id"],
              environ, **kwargs)
    try:
        state = transaction_session["state"]
    except KeyError:
        state = ""
    client_error_message(transaction_session["redirect_uri"], error,
                         error_description, state)


def _log_fail(logger, log_msg, transaction_id, client_id, environ, **kwargs):
    t = now()
    uid = get_new_error_uid()
    log_transaction_fail(logger, environ, transaction_id, client_id, log_msg,
                         timestamp=t, uid=uid, **kwargs)
    return t, uid


def client_error_message(redirect_uri, error="access_denied",
                         error_description="", state=""):
    """Construct an error response and send in fragment part of redirect_uri.
    :param redirect_uri: redirect_uri of the client
    :param error: OpenID Connect error code
    :param error_description: human readable description of the error
    """
    error_resp = AuthorizationErrorResponse(error=error,
                                            error_description=error_description,
                                            state=state)
    location = error_resp.request(redirect_uri, True)
    raise cherrypy.HTTPRedirect(location)


def negative_transaction_response(transaction_id, transaction_session, environ,
                                  logger, message, idp_entity_id):
    """Complete a transaction with a negative response (incorrect affiliation or no user consent).
    """
    _elapsed_transaction_time = get_timestamp() - transaction_session[
        "start_time"]
    log_negative_transaction_complete(logger, environ, transaction_id,
                                      transaction_session["client_id"],
                                      idp_entity_id,
                                      now(), _elapsed_transaction_time, message)
    try:
        state = transaction_session["state"]
    except KeyError:
        state = ""
    client_error_message(transaction_session["redirect_uri"], "access_denied",
                         message, state)