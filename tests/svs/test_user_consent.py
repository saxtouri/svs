import os
from datetime import datetime
from unittest.mock import Mock

import pkg_resources
import pytest
from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import InternalResponse, AuthenticationInformation
from satosa.micro_services import consent

from svs.user_consent import UserConsent


class TestUserConsent:
    @pytest.fixture
    def context(self, context):
        context.state[consent.STATE_KEY] = {'filter': ['affiliation', 'domain']}
        return context

    @pytest.fixture
    def internal_resp(self):
        resp = InternalResponse(AuthenticationInformation(None, str(datetime.now()), 'https://idp.example.com'))
        resp.requester = 'client1'
        resp.user_id = 'user1'
        resp.attributes['affiliation'] = ['student']
        return resp

    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = UserConsent(name='UserConsent', base_url='https://satosa.example.com')
        self.service.next = Mock()

    def test_process(self, context, internal_resp):
        resp = self.service.process(context, internal_resp)
        assert resp.status == '200 OK'
        assert 'consent' in resp.message

    def test_accept_consent(self, context, internal_resp):
        context.state[self.service.name] = {'internal_response': internal_resp.to_dict()}
        self.service.accept_consent(context)
        assert self.service.next.called
        assert self.service.name not in context.state

    def test_deny_consent(self, context):
        context.state[self.service.name] = {}
        with pytest.raises(SATOSAAuthenticationError):
            self.service.deny_consent(context)

        assert self.service.name not in context.state

    @pytest.mark.parametrize('lang, expected_word', zip(
        os.listdir(pkg_resources.resource_filename('svs', 'data/i18n/locale')),
        ['toestemming', 'pokračování', 'samtykke', 'Einverständnis', 'συγκατάθεση', 'consent', 'autorización',
         'nõusolekut', 'consentement', 'hozzájárulása', 'sutikimas', 'toestemming', 'consentimento', 'согласие',
         'medgivande']
    ))
    def test_language_change(self, context, internal_resp, lang, expected_word):
        context.request = {'lang': lang}
        context.state[self.service.name] = {'internal_response': internal_resp.to_dict()}

        resp = self.service.change_language(context)
        assert resp.status == '200 OK'
        assert expected_word in resp.message
