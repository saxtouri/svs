__author__ = 'regu0004'

# SAML attribute to verify affiliation with
AFFILIATION_ATTRIBUTE = 'eduPersonAffiliation'

# Values the RP can request in OpenID Connect parameter 'scope' in the Auth req.
PERSISTENT_NAMEID = 'persistent'
TRANSIENT_NAMEID = 'transient'

# Supported claims in the Auth req
DOMAIN = 'domain'
COUNTRY = 'country'


def get_affiliation_function(scope):
    """Returns the comparison function for the affiliation specified in the requested scope.

    :param scope: requested scope from the RP
    :return: function to verify the users affiliation
    """
    for affiliation in AFFILIATIONS:
        if affiliation in scope:
            return AFFILIATIONS[affiliation]


def _is_student(identity):
    return 'student' in _get_affiliation_attribute(identity)


def _is_member(identity):
    return 'member' in _get_affiliation_attribute(identity)


def _is_employee(identity):
    accepted_values = ['faculty', 'staff']
    return _contains_any(accepted_values, _get_affiliation_attribute(identity))


def _is_affiliated(identity):
    return _is_student(identity) or _is_employee(identity) or _is_member(identity)


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
    'employee': _is_employee,
    'alum': _is_alumni
}

# All scope values we understand
SCOPE_VALUES = AFFILIATIONS.keys() + [PERSISTENT_NAMEID, TRANSIENT_NAMEID]