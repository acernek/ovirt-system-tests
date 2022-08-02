#
# Copyright oVirt Authors
# SPDX-License-Identifier: GPL-2.0-or-later
#

import hashlib
import logging
import os
import re
import sys

from jenkins_utils.artifacts import JenkinsArtifacts
from jenkins_utils.ost import OSTRun


logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)


IPV4_REGEX = re.compile(
    r":?(?<!\.)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})(?!\.)"
)
IPV6_REGEX = re.compile(r"(([a-f0-9]{0,4})?(:([a-f0-9]{0,4})?){2,7})(?!:)")
MEM_REGEX = re.compile(r"0x([a-f0-9]{2}){1,8}")
ID_REGEX = re.compile(r"[0-9a-f]{8}[-]?(?:[0-9a-f]{4}[-]?){3}[0-9a-f]{12}")


def are_run_results_equal(run0: "OSTRun", run1: "OSTRun") -> bool:
    if run0.json_data.successful() or run1.json_data.successful():
        return run0.json_data.successful() and run1.json_data.successful()

    artifacts0 = JenkinsArtifacts(run0.url)
    artifacts0_path = artifacts0.fetch_artifacts()
    artifacts1 = JenkinsArtifacts(run1.url)
    artifacts1_path = artifacts1.fetch_artifacts()

    return anonymize_hash(os.path.join(artifacts0_path, "results.txt")) == anonymize_hash(
        os.path.join(artifacts1_path, "results.txt")
    )


def anonymize_hash(results: str) -> bytes:
    hasher = hashlib.sha256()
    with open(results, "r") as f:
        for line in f.readlines():
            for func in [anonymize_ipv4, anonymize_ipv6, anonymize_mem, anonymize_id]:
                line = func(line)
            hasher.update(line.encode("utf-8"))
    return hasher.digest()


def anonymize_ipv4(line: str) -> str:
    return re.sub(IPV4_REGEX, "0.0.0.0", line)


def anonymize_ipv6(line: str) -> str:
    return re.sub(IPV6_REGEX, "0.0.0.0", line)


def anonymize_mem(line: str) -> str:
    return re.sub(MEM_REGEX, "0xff", line)


def anonymize_id(line: str) -> str:
    return re.sub(ID_REGEX, "ffffffff-ffff-ffff-ffff-ffffffffffff", line)


# self-test
if __name__ == "__main__":
    # IPV4 tests
    for ip in ["0.0.0.0", "255.255.255.255", "1.11.111.1"]:
        assert anonymize_ipv4(ip) == "0.0.0.0", ip
        assert anonymize_ipv4(f"dsd {ip} dsds") == "dsd 0.0.0.0 dsds", ip
        assert anonymize_ipv4(f"'{ip}/24'") == "'0.0.0.0/24'", ip

    ip = "255.255.255.255 1.11.111.1"
    a = anonymize_ipv4(ip)
    assert a == "0.0.0.0 0.0.0.0", f"{a} != 0.0.0.0 0.0.0.0"

    for ip in ["akfl.sjd.kja.ksd", "256.256.256.256", "1.1.1.1.1"]:
        a = anonymize_ipv4(ip)
        assert a == ip, f"{a} != {ip}"

    # IPV6 tests
    for ip in [
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db8:73:1::ffff:ffff:0",
        "::",
        "::ffff:0:0",
        "2001:0000::",
    ]:
        assert anonymize_ipv6(ip) == "0.0.0.0", ip
        assert anonymize_ipv6(f"dsd {ip} dsds") == "dsd 0.0.0.0 dsds", ip
        assert anonymize_ipv6(f"'{ip}/24'") == "'0.0.0.0/24'", ip

    run0 = OSTRun(sys.argv[1])
    run1 = OSTRun(sys.argv[2])
    print(are_run_results_equal(run0, run1))
