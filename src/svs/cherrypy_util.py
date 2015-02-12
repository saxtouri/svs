import cherrypy
from cherrypy._cpdispatch import Dispatcher, LateParamPageHandler
from oic.utils.http_util import Redirect, SeeOther

__author__ = 'regu0004'


def send_418():
    """Set the response status to 418 ("I'm a teapot").
    """
    cherrypy.response.status = 418
    cherrypy.response.body = ''


def response_to_cherrypy(response):
    """Convert between internal response (oic.utils.http_util.Response) and CherryPy response.

    :param response: response to return
    :return: response content if the response is not a redirect, in which case a cherrypy.HTTPRedirect will be raised
    instead.
    """
    if isinstance(response, Redirect):
        raise cherrypy.HTTPRedirect(response.message, 302)
    elif isinstance(response, SeeOther):
        raise cherrypy.HTTPRedirect(response.message, 303)
    else:
        cherrypy.response.headers.update(dict(response.headers))
        return response.response(response.message)


class PathDispatcher(Dispatcher):
    """Simple dispatcher handling explicit mapping of paths to function.
    """

    def __init__(self, apps):
        """Copied from cherrypy.wsgiserver.wsgiserver2.WSGIPathInfoDispatcher.
        """

        try:
            apps = list(apps.items())
        except AttributeError:
            pass

        # Sort the apps by len(path), descending
        apps.sort(cmp=lambda x, y: cmp(len(x[0]), len(y[0])))
        apps.reverse()

        # The path_prefix strings must start, but not end, with a slash.
        # Use "" instead of "/".
        self.apps = [(p.rstrip("/"), a) for p, a in apps]

    def __call__(self, path_info):
        request = cherrypy.serving.request

        func = self.find_handler(path_info)
        if func is not None:
            request.handler = LateParamPageHandler(func)
            request.config = cherrypy.config.copy()
        else:
            request.handler = cherrypy.NotFound()

    def find_handler(self, path_info):
        for p, app in self.apps:
            # The apps list should be sorted by length, descending.
            if path_info == p:
                return app

        return None