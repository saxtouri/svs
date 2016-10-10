import os

import pkg_resources
from satosa.proxy_server import make_app as make_satosa
from satosa.satosa_config import SATOSAConfig
from werkzeug.wsgi import SharedDataMiddleware


def make_app():
    config_file = os.environ.get("SATOSA_CONFIG", "proxy_conf.yaml")
    satosa_config = SATOSAConfig(config_file)
    satosa = make_satosa(satosa_config)
    return SharedDataMiddleware(satosa, {
        '/consent.css': pkg_resources.resource_filename('svs', 'site/static/consent.css')
    })
