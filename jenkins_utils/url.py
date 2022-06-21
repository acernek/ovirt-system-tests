#
# Copyright oVirt Authors
# SPDX-License-Identifier: GPL-2.0-or-later
#
#

import functools
import re
import sys

from urllib import parse


class JenkinsUrl:
    def __init__(self, url: str):
        self._url = url if url[-1] == "/" else url + "/"

    @property
    def url(self) -> str:
        return self._url

    @functools.cached_property
    def json_url(self) -> str:
        return parse.urljoin(self.url, "api/json")

    @functools.cached_property
    def console_url(self) -> str:
        return parse.urljoin(self.url, "consoleFull")

    @functools.cached_property
    def artifacts_url(self) -> str:
        return parse.urljoin(self.url, "artifact/exported-artifacts/*zip*/exported-artifacts.zip")

    @functools.cached_property
    def build_number(self) -> int:
        m = re.match("^.*/([0-9]+)/$", self.url)
        if m is not None:
            return int(m.groups()[0])
        raise ValueError("URL doesn't contain a build number")

    def __repr__(self) -> str:
        return f"JenkinsUrl({self.url})"


def last_completed_build_for(url: 'JenkinsUrl') -> 'JenkinsUrl':
    return replace_build_number_in(url, "lastCompletedBuild")


def replace_build_number_in(url: 'JenkinsUrl', url_part: str) -> 'JenkinsUrl':
    parsed = parse.urlparse(url.url)
    path = parsed.path.split("/")
    path[-2] = url_part
    path = "/".join(path)
    return JenkinsUrl(parse.urlunparse(parsed._replace(path=path)))


# self-test
if __name__ == '__main__':
    url = JenkinsUrl(sys.argv[1])
    print(url.url)
    print(url.json_url)
    print(url.console_url)
    print(url.artifacts_url)
    print(url.build_number)
    print(last_completed_build_for(url))
