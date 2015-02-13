import unittest
import cherrypy
from mock import patch
from svs.cherrypy_util import PathDispatcher

__author__ = 'regu0004'


class TestPathDispatcher(unittest.TestCase):
    FOO = lambda: "foo"

    @patch('cherrypy.serving.request')
    def test_dispatch(self, req):
        path = "/foo"
        pd = PathDispatcher({path: TestPathDispatcher.FOO})
        pd(path)
        assert req.handler.callable == TestPathDispatcher.FOO

    @patch('cherrypy.serving.request')
    def test_dispatch_subdir(self, req):
        path = "/foo/bar"
        pd = PathDispatcher({path: TestPathDispatcher.FOO})
        pd(path)
        assert req.handler.callable == TestPathDispatcher.FOO

        pd(path.split("/")[0])
        assert isinstance(req.handler, cherrypy.NotFound)

    @patch('cherrypy.serving.request')
    def test_root(self, req):
        pd = PathDispatcher({"/": TestPathDispatcher.FOO})
        pd("")
        assert req.handler.callable == TestPathDispatcher.FOO

    @patch('cherrypy.serving.request')
    def test_trailing_slash(self, req):
        path = "/bar"
        pd = PathDispatcher({path + "/": TestPathDispatcher.FOO})
        pd(path)
        assert req.handler.callable == TestPathDispatcher.FOO

    @patch('cherrypy.serving.request')
    def test_not_found(self, req):
        path = "/bar"
        pd = PathDispatcher({path: TestPathDispatcher.FOO})
        pd("/noexist")
        assert isinstance(req.handler, cherrypy.NotFound)