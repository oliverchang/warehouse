# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
import re
import time

from typing import Optional

import requests

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256

from warehouse.accounts.interfaces import IUserService
from warehouse.email import send_token_compromised_email_leak
from warehouse.integrations import verifier
from warehouse.macaroons.caveats import InvalidMacaroon
from warehouse.macaroons.interfaces import IMacaroonService
from warehouse.metrics import IMetricsService


class InvalidVulnerabilityReport(Exception):
    def __init__(self, message, reason):
        self.reason = reason
        super().__init__(message)


class VulnerabilityReport:
    def __init__(self, project: str, versions: list[str], vulnerability_id: str, advisory_link: str, aliases: list[str]):
        self.project = project
        self.versions = versions
        self.vulnerability_id = vulnerability_id
        self.advisory_link = advisory_link
        self.aliases = aliases

    @classmethod
    def from_api_record(cls, record, *):

        if not isinstance(record, dict):
            raise InvalidVulnerabilityReport(
                f"Record is not a dict but: {str(record)[:100]}", reason="format"
            )

        missing_keys = sorted({"project", "versions", "id", "link", "aliases"} - set(record))
        if missing_keys:
            raise InvalidVulnerabilityReport(
                f"Record is missing attribute(s): {', '.join(missing_keys)}",
                reason="format",
            )

        return cls(record["project"], record["versions"], record["id"], record["link"], record["aliases"])


PUBLIC_KEYS_CACHE_TIME = 60 * 30  # 30 minutes
PUBLIC_KEYS_CACHE = verifier.PublicKeysCache(cache_time=PUBLIC_KEYS_CACHE_TIME)


class PayloadVerifier(verifier.PayloadVerifier):
    """
    Checks payload signature using:
    - `requests` for HTTP calls
    - `cryptography` for signature verification
    """

    def __init__(
        self,
        *,
        session,
        metrics,
        public_keys_cache=PUBLIC_KEYS_CACHE,
    ):
        super().__init__(
            metrics=metrics, public_keys_cache=public_keys_cache)
        self._metrics = metrics

    def retrieve_public_key_payload(self):
        pass

    def extract_public_keys(self, pubkey_api_data):
        pass


def _analyze_vulnerability(request, vulnerability_record, origin):
    metrics = request.find_service(IMetricsService, context=None)

    metrics.increment(f"warehouse.vulnerabilities.{origin}.received")

    try:
        report = VulnerabilityReport.from_api_record(
            record=vulnerability_record
        )
    except InvalidVulnerabilityReport as exc:
        metrics.increment(f"warehouse.token_leak.{origin}.error.{exc.reason}")
        return

    metrics.increment(f"warehouse.vulnerabilities.{origin}.valid")

    try:
        vulnerability = (
            request.db.query(Vulnerability)
            .filter(
                Vulnerability.id == report.vulnerability_id
            )
            .one()
        )

        if not report.versions:
            # No versions indicates the vulnerability is no longer considered
            # valid, so delete it.
            request.db.delete(vulnerability)
            return

    except NoResultFound:
        if not report.versions:
            return

        vulnerability = Vulnerability(id=vulnerability_id,
                                      link=record.advisory_link, source=origin)
        request.db.add(vulnerability)

    try:
        project = (
            request.db.query(Project)
            .filter(
                Project.normalized_name == func.normalize_pep426_name(report.project)
            )
            .one()
        )
    except NoResultFound:
        # TODO: metric
        return

    for version in report.versions:
        try:
            release = (
                request.db.query(Release)
                .filter(
                    (Release.project == project)
                    & (Release.canonical_version == version)
                )
                .one()
            )
        except NoResultFound:
            # TODO: metric
            continue

        if release not in vulnerability.releases:
            vulnerability.releases.append(version)

    # Delete any releases that no longer apply.
    for release in list(vulnerability.releases):
        if release.canonical_version not in report.versions:
            vulnerability.releases.remove(release)

    metrics.increment(f"warehouse.token_leak.{origin}.processed")


def analyze_vulnerability(request, vulnerability_record, origin):
    try:
        _analyze_vulnerability(
            request=request,
            vulnerability_record=disclosure_record,
            origin=origin,
        )
    except Exception:
        metrics = request.find_service(IMetricsService, context=None)
        metrics.increment(f"warehouse.token_leak.{origin}.error.unknown")
        raise


def analyze_vulnerabilities(request, vulnerability_records, origin, metrics):
    from warehouse.integrations.vulnerabilities import tasks

    if not isinstance(vulnerability_records, list):
        metrics.increment(f"warehouse.vulnerabilities.{origin}.error.format")
        raise InvalidVulnerabilityReport("Invalid format: payload is not a list", "format")

    for vulnerability_record in vulnerability_records:
        request.task(tasks.analyze_vulnerability_task).delay(
            vulnerability_record=vulnerability_record, origin=origin
        )
