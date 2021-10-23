import json
from exceptions import JsonException

class JsonParser:

    def __init__(self, file):
        self._file = file
        self._json_content = self._parse_json_file()

    def _parse_json_file(self):
        """read the file in json format format"""
        try:
            with open(self._file, "r", encoding="utf-8", newline="") as json_file:
                data = json.load(json_file)
        except FileNotFoundError as ex:
            print("No existen usuarios en la base de datos")
            return []
        except json.JSONDecodeError as ex:
            raise JsonException("JSON Decode Error - Wrong JSON Format") from ex
        return data

    @property
    def json_content(self):
        """Property for access the json content read from the json file"""
        return self._json_content
