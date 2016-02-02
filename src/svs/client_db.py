import json


class ClientDB(object):
    def __init__(self, filename):
        self.filename = filename
        self.data = {}

    def __getitem__(self, client_id):
        return self.data[client_id]

    def update(self):
        try:
            f = open(self.filename)
        except IOError as e:  # bad filename
            self.data = {}
            return

        with f:
            try:
                new_data = json.loads(f.read())
                self.data = new_data
            except ValueError as e:  # not JSON data in the file
                self.data = {}
                return
