import pytest
from saml2.config import SPConfig
from saml2.response import AuthnResponse
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT
from saml2.sigver import security_context
from satosa.exception import SATOSAAuthenticationError
from satosa.state import State

from svs.inacademia_backend import InAcademiaBackend


class TestInAcademiaBackend:
    @pytest.fixture
    def authn_resp(self):
        authn_resp = AuthnResponse(security_context(SPConfig()), None, 'https://sp.example.com',
                                   allow_unsolicited=True, return_addrs=['http://sp.example.com/demo1/index.php?acs'])

        xmlstr = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/acs" InResponseTo="abc123">
              <saml:Issuer>https://idp.example.com</saml:Issuer>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
              <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject>
                  <saml:NameID SPNameQualifier="https://sp.example.com" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="https://sp.example.com/acs" InResponseTo="abc123"/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
                  <saml:AudienceRestriction>
                    <saml:Audience>https://sp.example.com</saml:Audience>
                  </saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
                  <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                  </saml:AuthnContext>
                </saml:AuthnStatement>
                <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
              </saml:Assertion>
            </samlp:Response>"""

        authn_resp.loads(xmlstr)
        authn_resp.parse_assertion()
        return authn_resp

    @pytest.fixture(autouse=True)
    def create_backend(self):
        self.backend = InAcademiaBackend(lambda: None, {'attributes': {}},
                                         {'sp_config': {}, 'persistent_required': True},
                                         base_url='https://example.com',
                                         name='InAcademiaBackend')

    def test_get_user_id_form_persistent_nameid_from_persistent_nameid(self, authn_resp):
        authn_resp.assertion.subject.name_id.format = NAMEID_FORMAT_PERSISTENT
        authn_resp.assertion.subject.name_id.text = 'persistent nameid'
        assert self.backend._get_user_id(authn_resp) == 'persistent nameid'

    def test_get_user_id_form_persistent_nameid_from_eptid(self, authn_resp):
        authn_resp.ava['eduPersonTargetedID'] = ['edupersontargetedid']
        assert self.backend._get_user_id(authn_resp) == 'edupersontargetedid'

    def test_get_user_id_form_persistent_nameid_from_eppn(self, authn_resp):
        authn_resp.ava['eduPersonPrincipalName'] = ['edupersonprincipalname']
        internal_resp = self.backend._get_user_id(authn_resp)
        assert self.backend._get_user_id(authn_resp) == 'edupersonprincipalname'

    def test_get_user_id_prefer_eptid_over_eppn(self, authn_resp):
        authn_resp.ava['eduPersonTargetedID'] = ['edupersontargetedid']
        authn_resp.ava['eduPersonPrincipalName'] = ['edupersonprincipalname']
        assert self.backend._get_user_id(authn_resp) == 'edupersontargetedid'

    def test_get_user_id_should_use_transient_nameid_if_persistent_is_not_required(self, authn_resp):
        self.backend.persistent_required = False
        authn_resp.assertion.subject.name_id.format = NAMEID_FORMAT_TRANSIENT
        authn_resp.assertion.subject.name_id.text = 'transient nameid'
        authn_resp.ava['eduPersonTargetedID'] = ['edupersontargetedid']
        authn_resp.ava['eduPersonPrincipalName'] = ['edupersonprincipalname']

        assert self.backend._get_user_id(authn_resp) == 'transient nameid'

    def test_get_user_id_if_no_persistent_nameid_can_be_formed(self, authn_resp):
        assert self.backend._get_user_id(authn_resp) is None

    def test_translate_response_should_raise_exception_if_no_persistent_nameid_can_be_formed(self, authn_resp):
        authn_resp.ava['eduPersonAffiliation'] = 'affiliated'
        with pytest.raises(SATOSAAuthenticationError):
            self.backend._translate_response(authn_resp, State())

    def test_translate_response_should_raise_exception_if_no_affiliation_is_in_the_response(self, authn_resp):
        authn_resp.ava.pop('eduPersonAffiliation', None)
        with pytest.raises(SATOSAAuthenticationError):
            self.backend._translate_response(authn_resp, State())
