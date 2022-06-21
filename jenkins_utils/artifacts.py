#
# Copyright oVirt Authors
# SPDX-License-Identifier: GPL-2.0-or-later
#
#

import functools
import logging
import os
import shutil
import sys
import tempfile
import zipfile

import requests

from jenkins_utils.cache import JenkinsCache
from jenkins_utils.url import JenkinsUrl


logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)


class JenkinsArtifacts:
    def __init__(self, url: "JenkinsUrl"):
        self._url = url
        self._cache = JenkinsCache()

    @functools.cached_property
    def local_path(self) -> str:
        return self._cache.artifacts_path_for(self._url.build_number)

    def fetch_artifacts(self) -> str:
        LOGGER.debug(f"fetching artifacts for {self._url}")

        if os.path.isdir(self.local_path):
            LOGGER.debug(f"artifacts for {self._url} found in cache")
            return self.local_path

        artifacts_zipfile_path = self._cache.artifacts_zipfile_path_for(self._url.build_number)

        LOGGER.debug(f"downloading artifacts for {self._url}")
        with requests.get(self._url.artifacts_url, stream=True) as r:
            r.raise_for_status()
            with open(artifacts_zipfile_path, "wb") as artifacts_file:
                for chunk in r.iter_content(chunk_size=8192):
                    artifacts_file.write(chunk)

        LOGGER.debug(f"artifacts for {self._url} downloaded, unzipping")
        with zipfile.ZipFile(artifacts_zipfile_path, "r") as zip_file:
            with tempfile.TemporaryDirectory() as temp_dir:
                zip_file.extractall(temp_dir)
                bad_extracted_artifacts_path = os.path.join(temp_dir, "exported-artifacts")
                shutil.move(bad_extracted_artifacts_path, self.local_path)

        LOGGER.debug(f"artifacts for {self._url} fetched successfully")
        return self.local_path


# self-test
if __name__ == "__main__":
    url = JenkinsUrl(sys.argv[1])
    artifacts = JenkinsArtifacts(url)
    print(artifacts.fetch_artifacts())
