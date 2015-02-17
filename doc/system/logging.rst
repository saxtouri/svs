Logging
=======

Currently four (4) different log files are generated from the InAcademia core:

1. **svs_access.log**
    All incoming requests to the node, as written by CherryPy (formatted as
    `Combined Log Format <http://httpd.apache.org/docs/2.0/logs.html#combined>`_).

2. **svs_transactions.log**
    The entries in this log closely resembles the Common Log Format.

    An initiated transaction is logged as::

        <client_ip> - - [<date>] <client ID of RP> transaction_start <scope> <redirect_uri> <transaction_id>

    A completed transaction is logged as::

        <client_ip> - - [<date>] <client_id> transaction_complete idp=<idp> auth_time=<auth_time> extra_claims=<extra_claims> id_token=<id_token> elapsed_transaction_time=<transaction_time> <transaction_id>

4. **svs_tech.log**
    All transaction log messages as described above with additional debug logging.


The logging configuration can be found in ``conf/logging_conf.json``.


.. list-table:: Parameter substitution in log format
    :widths: 20 80
    :header-rows: 1

    * - Parameter
      - Value

    * - <date>
      - day/month/year:hour:minute:second

    * - <client_id>
      - RP's registered client id with the InAcademia service

    * - <transaction_id>
      - unique identifier for the transaction (the encoded Relay State is used)

    * - <scope>
      - the scope requested by the RP

    * - <redirect_uri>
      - the redirect URI given by the RP in the authentication request

    * - <idp>
      - entity id of the IdP that was part of the transaction

    * - <auth_time>
      - auth time as provided by the IdP

    * - <extra_claims>
      - any additional claims (country, domain) delivered

    * - <id_token>
      - the entire id token as a JWT

    * - <transaction_time>
      - time elapsed from the start to the end of the transaction


What is logged
--------------

A successful transaction will generate three important log messages:

.. list-table:: Log messages in successful transaction
    :widths: 80 20
    :header-rows: 1

    * - Event
      - Key in logs

    * - Start of transaction (incoming authentication request)
      - ``transaction_start``

    * - End users choice of IdP at discovery server (response from discovery server)
      - ``idp_chosen``

    * - Completed transaction
      - ``transaction_complete`` (successful authentication response) or ``negative_transaction_complete``
        (``access_denied`` error response)

When a transaction is failed, either due to an invalid authentication request (technically before any transaction has
started) or because of some error, the log message will have the key ``transaction_failed`` in the logs.

