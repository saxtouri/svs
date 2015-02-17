Filter implementation details
#############################


Affiliation validation
======================

The affiliation is validated using the SAML attribute ``eduPersonAffiliation``. The following table shows the mapping
between scopes requested by RP's in the authentication request and the values of ``eduPersonAffiliation``

.. list-table:: Mapping between scope and accepted values for the affiliation attribute.
    :widths: 30 70
    :header-rows: 1

    * - Requested scope
      - Accepted values in ``eduPersonAffiliation`` attribute

    * - student
      - student

    * - alum
      - alum

    * - faculty+staff
      - faculty, staff

    * - affiliated
      - student, faculty, staff, member


.. _choose_name_id:

Choose name id
==============

::

    If a transient user id is requested by the RP:
        Use the SAML nameID if it is transient.

    If a persistent user id is requested by the RP:
        Choose (in order) from the following list:

        1. Persistent SAML nameID
        2. eduPersonTargetedId
        3. eduPersonPrincipalName

    If none of the above attributes can be used, the transaction will fail.


Additional claims
=================

If the RP requests additional claims (country, domain) they will be returned if they can be found
and the RP is allowed to fetch them. See :ref:`Additional claims user doc <additional_claims>`.

The country information about the IdP is fetched directly from the metadata delivered by the MDX server, while the
domain is read from the `schacHomeOrganization` attribute in the authentication response from the IdP.
