import argparse
import copy
import json
import os
import urlparse

from saml2.config import Config
from saml2.metadata import entity_descriptor, metadata_tostring_fix
from saml2.validate import valid_instance

from svs.filter import PERSISTENT_NAMEID, TRANSIENT_NAMEID


def _merge_configs(default, extra):
    result = copy.deepcopy(default)
    result["service"]["sp"].update(extra["service"]["sp"])
    result["entityid"] = extra["entityid"]

    return result


def make_metadata(base):
    sp_configs = load_sp_config(base)
    write_metadata(sp_configs)

    return sp_configs


def load_sp_config(base):
    with open("conf/sp_default.json", "r") as f:
        default_config = json.load(f)
    with open("conf/sp_persistent.json", "r") as f:
        persistent_config = json.load(f)
    with open("conf/sp_transient.json", "r") as f:
        transient_config = json.load(f)

    for key, value in default_config["service"]["sp"]["endpoints"].iteritems():
        for endpoint in value:
            endpoint[0] = endpoint[0].format(base=base)

    persistent_config = _merge_configs(default_config, persistent_config)
    transient_config = _merge_configs(default_config, transient_config)

    sp_configs = {
        PERSISTENT_NAMEID: persistent_config,
        TRANSIENT_NAMEID: transient_config,
    }

    return sp_configs


def write_metadata(sp_configs):
    """
    Generate SAML XML metadata from the pysaml2 JSON format.
    :param base: base url of the svs node
    :return: dictionary with the config for the two SP's
    """

    for _, config in sp_configs.iteritems():
        cnf = Config().load(config, metadata_construction=True)
        eid = entity_descriptor(cnf)
        valid_instance(eid)
        nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
        xmldoc = metadata_tostring_fix(eid, nspair, None)

        entity_id = config["entityid"]
        path = urlparse.urlparse(entity_id).path
        filename = os.path.basename(path)
        with open(filename, "w") as output_file:
            output_file.write(xmldoc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("base", type=str, help="base url of the SP")
    args = parser.parse_args()

    make_metadata(args.base)