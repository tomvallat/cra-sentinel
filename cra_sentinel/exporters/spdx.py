"""SPDX 2.3 SBOM export (the alternative format accepted under the CRA)."""
from __future__ import annotations

import re
import uuid


def _spdx_id(prefix: str, value: str) -> str:
    return f"SPDXRef-{prefix}-{re.sub(r'[^A-Za-z0-9.-]', '-', value)}"


def build(scan, supplier: str = "") -> dict:
    namespace = f"https://spdx.org/spdxdocs/{scan.project_name}-{uuid.uuid4()}"
    root_id = _spdx_id("Product", f"{scan.project_name}-{scan.project_version}")

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{scan.project_name}-{scan.project_version}-sbom",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": scan.scanned_at,
            "creators": [f"Tool: CRA-Sentinel-{scan.tool_version}"]
                        + ([f"Organization: {supplier}"] if supplier else []),
            "licenseListVersion": "3.22",
        },
        "packages": [{
            "SPDXID": root_id,
            "name": scan.project_name,
            "versionInfo": scan.project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": f"Organization: {supplier}" if supplier else "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }],
        "relationships": [{
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }],
    }

    seen = set()
    for component in scan.components:
        pid = _spdx_id("Package", f"{component.full_name}-{component.version}")
        if pid in seen:
            continue
        seen.add(pid)
        licenses = component.licenses or []
        doc["packages"].append({
            "SPDXID": pid,
            "name": component.full_name,
            "versionInfo": component.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": licenses[0] if len(licenses) == 1 else "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component.purl,
            }],
        })
        doc["relationships"].append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON" if component.direct else "CONTAINS",
            "relatedSpdxElement": pid,
        })

    return doc
