import cherrypy
from mako.lookup import TemplateLookup
import pkg_resources

from svs.i18n_tool import ugettext_lazy as N_


__author__ = 'regu0004'

LOOKUP = TemplateLookup(directories=[pkg_resources.resource_filename("svs", "templates")], module_directory='modules/',
                        input_encoding='utf-8', output_encoding='utf-8',
                        imports=["from svs.i18n_tool import ugettext as _"])


class EndUserErrorResponse(cherrypy.HTTPError):
    def __init__(self, timestamp, uid, message, form_action="/error"):
        error = {
            "uid": uid,
            "timestamp": self._format_timestamp(timestamp),
            "message": message,
        }

        argv = {
            "error": error,
            "language": cherrypy.response.i18n.locale.language,
            "form_action": form_action
        }

        self.error_page = LOOKUP.get_template("error.mako").render(**argv)
        super(EndUserErrorResponse, self).__init__(400, self.error_page)

    def _format_timestamp(self, timestamp):
        return str(timestamp)

    def get_error_page(self, *args, **kwargs):
        return self.error_page


class ConsentPage(object):
    """
    Render the consent page.
    """

    TEMPLATE = "consent.mako"

    @classmethod
    def render(cls, client_name, idp_entity_id, released_claims, relay_state, form_action="/consent"):
        question = N_("<strong>'{client_name}'</strong> requires the information below to be transferred:").format(
            client_name=client_name)

        state = {
            "idp_entity_id": idp_entity_id,
            "state": relay_state,
        }

        return LOOKUP.get_template(cls.TEMPLATE).render(consent_question=question,
                                                        released_claims=released_claims,
                                                        state=state,
                                                        form_action=form_action,
                                                        language=cherrypy.response.i18n.locale.language)