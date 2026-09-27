from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
README = ROOT / "README.md"
README_POLICY = ROOT / "ci" / "readme-policy"


def _job_sections(workflow: str) -> dict[str, str]:
    jobs = re.search(r"(?m)^jobs:\s*$", workflow)
    assert jobs is not None
    body = workflow[jobs.end() :]
    matches = list(re.finditer(r"(?m)^  ([A-Za-z0-9-]+):\s*$", body))
    return {
        match.group(1): body[
            match.start() : matches[index + 1].start() if index + 1 < len(matches) else len(body)
        ]
        for index, match in enumerate(matches)
    }


def test_readme_policy_uses_same_locked_upstream_tooling_as_imagemd() -> None:
    package = json.loads((README_POLICY / "package.json").read_text(encoding="utf-8"))
    remark = json.loads((README_POLICY / ".remarkrc.json").read_text(encoding="utf-8"))

    assert "scripts" not in package
    assert package["devDependencies"] == {
        "remark-cli": "12.0.1",
        "remark-preset-lint-consistent": "6.0.1",
        "remark-preset-lint-recommended": "7.0.1",
        "standard-readme-preset": "1.0.13",
    }
    assert remark["plugins"] == [
        "standard-readme-preset",
        [
            "standard-readme-preset/rules/require-sections.js",
            {"installable": True},
        ],
        "remark-preset-lint-recommended",
        "remark-preset-lint-consistent",
    ]


def test_quality_job_enforces_readme_policy_fail_closed() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    quality = _job_sections(workflow)["quality"]

    assert (
        "docker.io/library/node:24.14.1-bookworm-slim@"
        "sha256:b506e7321f176aae77317f99d67a24b272c1f09f1d10f1761f2773447d8da26c" in quality
    )
    assert '--volume "$PWD:/JameFirewall"' in quality
    assert "--workdir /JameFirewall" in quality
    assert "NPM_CONFIG_IGNORE_SCRIPTS=true npm ci" in quality
    assert (
        "ci/readme-policy/node_modules/.bin/remark README.md --frail "
        "--rc-path ci/readme-policy/.remarkrc.json" in quality
    )
    assert (
        "lycheeverse/lychee:0.24.2@"
        "sha256:e2d19e57cf6ab037026f20b8e449a1f30d9d7f81eef4194763aab2eab20bd28d" in quality
    )
    assert '--volume "$PWD:/JameFirewall:ro"' in quality
    assert "--no-progress --root-dir . README.md" in quality
    assert "|| true" not in quality
    assert "continue-on-error" not in quality


def test_readme_has_canonical_english_structure() -> None:
    readme = README.read_text(encoding="utf-8")
    headings = re.findall(r"(?m)^## ([^\n]+)$", readme)

    assert readme.startswith("# JameFirewall\n")

    expected = [
        "Table of Contents",
        "Install",
        "Usage",
        "Architecture",
        "Development",
        "Releases",
        "Contributing",
        "License",
    ]
    positions = [headings.index(section) for section in expected]
    assert positions == sorted(positions)

    for legacy in (
        "Arquitectura",
        "Desarrollo",
        "Requisitos",
        "Entorno y Comprobaciones de Calidad",
    ):
        assert f"## {legacy}" not in readme
        assert f"### {legacy}" not in readme


def test_required_ci_keeps_readme_enforcement_inside_existing_quality_authority() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    sections = _job_sections(workflow)
    required = sections["required-ci"]

    assert "quality" in required
    assert "documentation" not in sections
    assert "README.md" not in required
