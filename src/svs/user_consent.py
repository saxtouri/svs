import gettext

import pkg_resources
from mako.lookup import TemplateLookup
from satosa.exception import SATOSAAuthenticationError
from satosa.internal_data import InternalResponse
from satosa.micro_services import consent
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Response


def N_(s):
    """
    Dummy function to mark strings for translation, but defer the actual translation for later (using the real "_()").
    :param s:
    :return:
    """
    return s


class UserConsent(ResponseMicroService):
    """
    Select which backend should be used based on what the OIDC scope is.
    """

    def __init__(self, *args, **kwargs):
        """
        Constructor.
        """
        super().__init__(*args, **kwargs)

        self.endpoint = '/handle_consent'
        self.template_lookup = TemplateLookup(directories=[pkg_resources.resource_filename('svs', 'templates/')])

    def _find_requester_name(self, requester_name, language):
        return requester_name
        # requester_names = {entry['lang']: entry['text'] for entry in requester_name}
        # # fallback to english, or if all else fails, use the first entry in the list of names
        # fallback = requester_names.get('en', requester_name[0]['text'])
        # return requester_names.get(language, fallback)

    def _attributes_to_release(self, internal_response):
        attributes = {
            N_('Affiliation'): internal_response.attributes['affiliation'],
            N_('Identifier'): internal_response.user_id,
            N_('Authentication time'): internal_response.auth_info.timestamp
        }
        if 'domain' in internal_response.attributes:
            attributes[N_('Domain')] = internal_response.attributes['domain']

        return attributes

    def render_consent(self, internal_response, language='en'):
        requester_name = self._find_requester_name(internal_response.requester, language)
        gettext.translation('messages', localedir=pkg_resources.resource_filename('svs', 'data/i18n/locale'),
                            languages=[language]).install()

        released_attributes = self._attributes_to_release(internal_response)
        template = self.template_lookup.get_template('consent.mako')
        page = template.render(client_name=requester_name,
                               released_attributes=released_attributes,
                               form_action='/consent{}'.format(self.endpoint),
                               language=language)

        return Response(page, content='text/html')

    def process(self, context, internal_response):
        """
        Ask the user for consent of data to be released.
        :param context: request context
        :param internal_response: the internal response
        """
        consent_state = context.state[consent.STATE_KEY]
        internal_response.attributes = {k: v for k, v in internal_response.attributes.items() if
                                        k in consent_state['filter']}

        context.state[self.name] = {'internal_response': internal_response.to_dict()}
        return self.render_consent(internal_response)

    def accept_consent(self, context):
        """
        Endpoint for handling accepted consent.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """
        consent_state = context.state[self.name]
        saved_resp = consent_state['internal_response']
        internal_response = InternalResponse.from_dict(saved_resp)
        del context.state[self.name]
        return super().process(context, internal_response)

    def deny_consent(self, context):
        """
        Endpoint for handling denied consent.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """
        del context.state[self.name]
        raise SATOSAAuthenticationError(context.state, 'Consent was denied by the user.')

    def change_language(self, context):
        consent_state = context.state[self.name]
        saved_resp = consent_state['internal_response']
        internal_response = InternalResponse.from_dict(saved_resp)

        lang = context.request.get('lang', 'en')
        return self.render_consent(internal_response, lang)

    def register_endpoints(self):
        base = '^consent{}'.format(self.endpoint)
        url_map = []
        url_map.append(('{}$'.format(base), self.change_language))
        url_map.append(('{}/allow'.format(base), self.accept_consent))
        url_map.append(('{}/deny'.format(base), self.deny_consent))
        return url_map
