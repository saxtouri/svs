import cherrypy
from mako.lookup import TemplateLookup
import pkg_resources

from .i18n_tool import ugettext as _


__author__ = 'regu0004'

LOOKUP = TemplateLookup(directories=[pkg_resources.resource_filename("svs", "templates")], module_directory='modules/',
                        input_encoding='utf-8', output_encoding='utf-8',
                        imports=["from svs.i18n_tool import ugettext as _"])


class EndUserErrorResponse(cherrypy.HTTPError):
    def __init__(self, timestamp, uid, error_key, message, proposed_solution=None, form_action="/error"):
        if proposed_solution is None:
            proposed_solution = _("Please return to the service you were using and try again.")

        error = {
            "error_key": error_key,
            "uid": uid,
            "timestamp": self._format_timestamp(timestamp),
            "message": message,
            "proposed_solution": proposed_solution,
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
    def render(cls, base_url, rp_display_name, idp_entity_id, released_attributes, relay_state):
        question = _("consent_question").format(rp_display_name=rp_display_name)

        state = {
            "idp_entity_id": idp_entity_id,
            "state": relay_state,
        }

        return LOOKUP.get_template(cls.TEMPLATE).render(consent_question=question,
                                                        released_attributes=released_attributes,
                                                        state=state,
                                                        form_action="{}consent".format(base_url),
                                                        language=cherrypy.response.i18n.locale.language)