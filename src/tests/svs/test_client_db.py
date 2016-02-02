import json
import os

from svs.client_db import ClientDB


class TestClientDBSignalHandler(object):
    def write_to_file(self, filename, data):
        with open(filename, "w") as f:
            f.write(json.dumps(data))

    def test_loads_on_init(self, tmpdir):
        clients = {"client1": {"foo": "bar"}}
        filename = os.path.join(str(tmpdir) + "clients.json")
        self.write_to_file(filename, clients)

        cdb = ClientDB(filename)
        cdb.update()
        assert cdb["client1"] == {"foo": "bar"}

    def test_nonexistent_file(self):
        cdb = ClientDB("noexist")
        cdb.update()
        assert cdb.data == {}

    def test_non_json_file(self, tmpdir):
        filename = os.path.join(str(tmpdir) + "clients.json")
        with open(filename, "w") as f:
            f.write("foobar")

        cdb = ClientDB(filename)
        cdb.update()
        assert cdb.data == {}
