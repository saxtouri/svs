import rfc822

from .utils import now, get_new_error_uid


def log_transaction_start(logger, environ, transaction_id, client_id, scope, redirect_uri):
    msg = "transaction_start {} {}".format(scope, redirect_uri)
    _log_transaction(logger, environ, transaction_id, client_id, msg)


def log_transaction_complete(logger, environ, transaction_id, client_id, idp_entity_id, auth_time,
                             elapsed_transaction_time, extra_claims, id_token):
    msg = "transaction_complete idp={} auth_time={} elapsed_transaction_time={} extra_claims={} id_token={} ".format(
        idp_entity_id, auth_time, elapsed_transaction_time, extra_claims, id_token)
    _log_transaction(logger, environ, transaction_id, client_id, msg)


def log_negative_transaction_complete(logger, environ, transaction_id, client_id, idp_entity_id, auth_time,
                                      elapsed_transaction_time, message):
    msg = "negative_transaction_complete idp={} auth_time={} elapsed_transaction_time={} message={}".format(
        idp_entity_id, auth_time, elapsed_transaction_time, message)
    _log_transaction(logger, environ, transaction_id, client_id, msg)


def log_transaction_idp(logger, environ, transaction_id, client_id, idp):
    msg = "idp_chosen idp={}".format(idp)
    _log_transaction(logger, environ, transaction_id, client_id, msg)


def log_transaction_fail(logger, environ, transaction_id, client_id, message, timestamp=None, uid=None):
    if timestamp is None:
        timestamp = now()
    if uid is None:
        uid = get_new_error_uid()

    msg = "transaction_failed t={} uid={} {}".format(timestamp, uid, message)
    _log_transaction(logger, environ, transaction_id, client_id, msg)

def log_internal(logger, message, environ, transaction_id="-", client_id="-"):
    if environ is not None:
        prefix = _get_clf_prefix_string(environ)
    else:
        prefix = "- - - {}".format(_clf_time())

    msg = "{} {} {} {}".format(prefix, client_id, message, transaction_id)
    logger.debug(msg)

def _log_transaction(logger, environ, transaction_id, client_id, message):
    msg = "{} {} {} {}".format(_get_clf_prefix_string(environ), client_id, message, transaction_id)
    logger.info(msg)


def _get_clf_prefix_string(environ, timestamp=None):
    """
    Returns the prefix (containing IP address, identity, user id and timestamp) of the (Apache) Common Log Format.
    :param environ:
    :return:
    """
    tmpl = '%(h)s %(l)s %(u)s %(t)s'
    msg = tmpl % {
        'h': environ.remote.ip,
        'l': "-",
        'u': environ.login or "-",
        't': _clf_time(timestamp)
    }

    return msg


def _clf_time(timestamp=None):
    """Return the given timestamp (or now() if no timestamp was given) in (Apache) Common Log Format (no timezone)."""
    if timestamp is None:
        timestamp = now()

    month = rfc822._monthnames[timestamp.month - 1].capitalize()
    return ('[%02d/%s/%04d:%02d:%02d:%02d]' %
            (timestamp.day, month, timestamp.year, timestamp.hour, timestamp.minute, timestamp.second))

