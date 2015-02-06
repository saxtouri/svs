from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT

__author__ = 'regu0004'

# SAML attribute to verify affiliation with
AFFILIATION_ATTRIBUTE = 'eduPersonAffiliation'

# Values the RP can request in OpenID Connect parameter 'scope' in the Auth req.
PERSISTENT_NAMEID = 'persistent'
TRANSIENT_NAMEID = 'transient'
DOMAIN = 'domain'
COUNTRY = 'country'


def get_affiliation_function(scope):
    """
    Returns the comparison function for the affiliation specified in the requested scope.

    :param scope: requested scope from the RP
    :return: function to verify the users affiliation
    """
    for affiliation in AFFILIATIONS:
        if affiliation in scope:
            return AFFILIATIONS[affiliation]


def get_name_id(name_id_from_idp, identity, scope):
    """
    Generate the name id.

    If the RP requested a persistent name id, try the following SAML attributes in order:
        1. Persistent name id
        2. eduPersonTargetedId (EPTID)
        3. eduPersonPrincipalName (EPPN)
    :param name_id_from_idp: name id as given by the SAML Auth Response
    :param identity: SAML assertions
    :param scope: requested scope from the RP
    :return: the name id from the IdP or None if an incorrect or no name id at all was returned from the IdP.
    """
    name_id = None
    if PERSISTENT_NAMEID in scope:
        # Use one of NameID (if persistent) or EPTID or EPPN in that order
        if name_id_from_idp.format == NAMEID_FORMAT_PERSISTENT:
            name_id = name_id_from_idp.text
        else:
            for key in ['eduPersonTargetedID', 'eduPersonPrincipalName']:
                if key in identity:
                    name_id = identity[key][0]
                    break
    else:
        if name_id_from_idp.format == NAMEID_FORMAT_TRANSIENT:
            name_id = name_id_from_idp.text  # TODO is this transient name id really unique for each session?
        else:
            pass

    return name_id


def _is_student(identity):
    return 'student' in _get_affiliation_attribute(identity)


def _is_member(identity):
    return 'member' in identity[AFFILIATION_ATTRIBUTE]


def _is_faculty_or_staff(identity):
    accepted_values = ['faculty', 'staff']
    return _contains_any(accepted_values, _get_affiliation_attribute(identity))


def _is_affiliated(identity):
    return _is_student(identity) or _is_faculty_or_staff(identity) or _is_member(identity)


def _is_alumni(identity):
    return 'alum' in _get_affiliation_attribute(identity)


def _contains_any(accepted_values, bag):
    return any(v in bag for v in accepted_values)


def _get_affiliation_attribute(identity):
    """
    Return the list of affiliations.
    :param identity: attributes returned from IdP
    :return: list of affiliations, or empty list if the affiliation attribute does not exist
    """
    return identity.get(AFFILIATION_ATTRIBUTE, [])


# Mapping between the possible scope values for requesting verification of a certain affiliation
AFFILIATIONS = {
    'affiliated': _is_affiliated,
    'student': _is_student,
    'faculty+staff': _is_faculty_or_staff,
    'alum': _is_alumni
}