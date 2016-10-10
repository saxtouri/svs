import pytest
from satosa.context import Context

from svs.scope_based_routing import ScopeBasedRouting


class TestScopeBasedRouting:
    @pytest.fixture(autouse=True)
    def create_service(self):
        self.service = ScopeBasedRouting(name='ScopeBasedRouting', base_url='https://satosa.example.com')
        self.service.next = lambda ctx, data: (ctx, data)

    @pytest.mark.parametrize('id_type, expected_backend', [
        ('transient', 'SAML2Transient'),
        ('persistent', 'SAML2Persistent')
    ])
    def test_explicity_type_in_scope(self, id_type, expected_backend):
        context = Context()
        context.request = {'scope': 'openid student ' + id_type}
        self.service.process(context, None)
        assert context.target_backend == expected_backend

    def test_defaults_to_transient(self):
        context = Context()
        context.request = {'scope': 'openid student'}
        self.service.process(context, None)
        assert context.target_backend == 'SAML2Transient'
