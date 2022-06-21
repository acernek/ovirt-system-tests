#
# Copyright oVirt Authors
# SPDX-License-Identifier: GPL-2.0-or-later
#
#

import functools
import json
import sys

from typing import Optional

import requests

from jenkins_utils.url import JenkinsUrl
from jenkins_utils.cache import JenkinsCache


class JenkinsJson:
    def __init__(self, url: 'JenkinsUrl'):
        self._url = url
        self.cache = JenkinsCache()

    @property
    def url(self) -> 'JenkinsUrl':
        return self._url

    @functools.cache
    def full(self) -> dict:
        data = self._read_local_json()
        if data is not None:
            return data
        data = self._fetch_json()
        self._save_json_to_cache(data)
        return data

    @functools.cache
    def build_parameters(self) -> dict:
        data = self.full()
        params_action = data["actions"][0]
        assert params_action["_class"] == "hudson.model.ParametersAction"
        params = params_action["parameters"]
        return {p["name"]: p["value"] for p in params}

    @functools.cache
    def agent_name(self) -> str:
        return self.full()["builtOn"]

    @functools.cache
    def result(self) -> str:
        return self.full()["result"]

    def successful(self) -> bool:
        return self.result() == "SUCCESS"

    def failed(self) -> bool:
        return self.result() == "FAILURE"

    def _read_local_json(self) -> Optional[dict]:
        json_path = self.cache.json_path_for(self._url.build_number)
        try:
            with open(json_path) as json_file:
                return json.load(json_file)
        except FileNotFoundError:
            return None

    def _fetch_json(self) -> dict:
        result = requests.get(self._url.json_url)
        result.raise_for_status()
        return json.loads(result.text)

    def _save_json_to_cache(self, json_data: dict):
        json_path = self.cache.json_path_for(self._url.build_number)
        with open(json_path, "w") as json_file:
            json.dump(json_data, json_file, indent=2)


# self-test
if __name__ == '__main__':
    url = JenkinsUrl(sys.argv[1])
    _json = JenkinsJson(url)
    print(_json.url)
    print(_json.full())
    print(_json.build_parameters())
    print(_json.agent_name())
    print(_json.result())
    print(_json.successful())
    print(_json.failed())
