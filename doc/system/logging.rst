Logging
=======

Currently four (4) different log files are generated from the InAcademia core:

1. **svs_access.log**
    All incoming requests to the SVS node, follow the `Combined Log Format <http://httpd.apache.org/docs/2.0/logs.html#combined>`_,
    as written by CherryPy.

2. **svs_transactions.log**
    The entries in this log closely resembles the Common Log Format.

    An initiated transaction is logged as::

        <client_ip> - - [<date>] <client ID of RP> transaction_start <scope> <redirect_uri> <transaction_id>

    A completed transaction is logged as::

        <client_ip> - - [<date>] <client_id> transaction_complete idp=<idp> auth_time=<auth_time> extra_claims=<extra_claims> id_token=<id_token> elapsed_transaction_time=<transaction_time> <transaction_id>

3. **svs_transactions_error.log**
    **TODO both format and what is logged**

4. **svs_tech.log**
    All transaction log messages as described above with additional debug logging.


The logging configuration can be found in ``data/logging_conf.json``.


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
      - `transaction_start`

    * - End users choice of IdP at discovery server (response from discovery server)
      - `idp_chosen`

    * - Completed transaction
      - `transaction_complete`

When a transaction is failed, the log message will have the key `transaction_failed` in the logs.
If the incoming authentication request is invalid, the transaction is aborted (even though it has not technically
started yet) and the log message will have the key
`transaction_aborted`.

