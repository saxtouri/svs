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
    return _contains_any(['student'], _get_affiliation_attribute(identity))


def _is_member(identity):
    return _contains_any(['member'], _get_affiliation_attribute(identity))


def _is_employee(identity):
    return _contains_any(['employee'], _get_affiliation_attribute(identity))


def _is_affiliated(identity):
    return _is_student(identity) or _is_employee(identity) or _is_member(
        identity)


def _is_alumni(identity):
    return _contains_any(['alum'], _get_affiliation_attribute(identity))


def _is_faculty_or_staff(identity):
    return _contains_any(['faculty', 'staff'],
                         _get_affiliation_attribute(identity))


def _contains_any(accepted_values, bag):
    for v in accepted_values:
        if v in bag:
            return v

    return None


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
    'faculty+staff': _is_faculty_or_staff,
    'alum': _is_alumni
}

# All scope values we understand
SCOPE_VALUES = AFFILIATIONS.keys() + [PERSISTENT_NAMEID, TRANSIENT_NAMEID]