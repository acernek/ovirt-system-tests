#
# Copyright oVirt Authors
# SPDX-License-Identifier: GPL-2.0-or-later
#
#

import functools
import os

_CACHE_HOME = os.path.expandvars(os.environ.get("XDG_CACHE_HOME", "$HOME/.cache"))


class JenkinsCache:
    def __init__(self):
        pass

    @functools.cached_property
    def dir(self) -> str:
        path = os.path.join(_CACHE_HOME, "ost_analyze")
        os.makedirs(path, exist_ok=True)
        return path

    def json_path_for(self, build_number: int) -> str:
        return os.path.join(self.json_dir, f"{build_number}.json")

    def artifacts_path_for(self, build_number: int) -> str:
        return os.path.join(self.artifacts_dir, f"{build_number}")

    def artifacts_zipfile_path_for(self, build_number: int) -> str:
        return os.path.join(self.artifacts_dir, f"{build_number}.zip")

    @functools.cached_property
    def json_dir(self) -> str:
        path = os.path.join(self.dir, "json")
        os.makedirs(path, exist_ok=True)
        return path

    @functools.cached_property
    def artifacts_dir(self) -> str:
        path = os.path.join(self.dir, "artifacts")
        os.makedirs(path, exist_ok=True)
        return path


# self-test
if __name__ == '__main__':
    cache = JenkinsCache()
    print(cache.dir)
    print(cache.json_dir)
    print(cache.json_path_for(2020))
    print(cache.artifacts_dir)
