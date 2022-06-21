#
# Copyright oVirt Authors
# SPDX-License-Identifier: GPL-2.0-or-later
#
#

import logging
import sys
import typing

from collections import namedtuple
from typing import Optional

from jenkins_utils.json_data import JenkinsJson
from jenkins_utils.url import JenkinsUrl
from jenkins_utils.url import replace_build_number_in

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

OSTParams = namedtuple("OSTParams", "suite distro ip_version custom_repos ost_refspec")


def ost_params_from(json_data: "JenkinsJson") -> OSTParams:
    params = json_data.build_parameters()
    suite = params["SUITE_NAME"]
    distro = params["OST_IMAGE"].split("+")[0]
    ip_version = params["IP_VERSION"]
    custom_repos = params["CUSTOM_REPOS"].strip()
    custom_repos = custom_repos.split(" ") if custom_repos else []
    ost_refspec = params["OST_REFSPEC"]
    return OSTParams(suite, distro, ip_version, custom_repos, ost_refspec)


class OSTRun:
    def __init__(self, url: typing.Union[str, JenkinsUrl]):
        self._url = url if isinstance(url, JenkinsUrl) else JenkinsUrl(url)
        self._json_data = JenkinsJson(self._url)
        self._params = ost_params_from(self._json_data)

    @property
    def url(self):
        return self._url

    @property
    def json_data(self):
        return self._json_data

    @property
    def params(self):
        return self._params


def find_previous_matching_build(
    ost_run: OSTRun, only_successful: bool = True, max_builds: int = 100
) -> Optional[OSTRun]:
    LOGGER.debug(f"looking for a matching build for {ost_run.params}")
    for i in range(1, max_builds + 1):
        build_no_candidate = str(ost_run.json_data.url.build_number - i)
        LOGGER.debug(f"checking {build_no_candidate}")
        url_candidate = replace_build_number_in(ost_run.json_data.url, build_no_candidate)
        ost_run_candidate = OSTRun(url_candidate)

        if only_successful and not ost_run_candidate.json_data.successful():
            LOGGER.debug(f"build {build_no_candidate} is not successful")
            continue

        LOGGER.debug(f"params for {build_no_candidate}: {ost_run_candidate.params}")

        if ost_run_candidate.params == ost_run.params:
            LOGGER.debug(f"build {build_no_candidate} is a match")
            return ost_run_candidate

    return None


# self-test
if __name__ == "__main__":
    ost_run = OSTRun(sys.argv[1])
    print(ost_run)
    print(find_previous_matching_build(ost_run))
