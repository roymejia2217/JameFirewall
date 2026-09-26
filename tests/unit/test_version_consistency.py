import json
import re
import tomllib
from pathlib import Path

import pytest

import jame_firewall


@pytest.mark.unit
def test_manifest_and_source_versions_are_strictly_in_lockstep() -> None:
    """Verifica el contrato de invariancia: el manifiesto de Google, pyproject.toml y __init__.py

    deben mantener sincronía atómica idéntica. Si un archivo sufre drift, el Quality Gate
    falla inmediatamente.
    """
    root_dir = Path(__file__).resolve().parent.parent.parent

    # 1. Manifiesto de Google Release-Please
    manifest_file = root_dir / ".release-please-manifest.json"
    assert manifest_file.exists(), "Falta el manifiesto canónico .release-please-manifest.json"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    manifest_ver = manifest_data.get(".")
    assert manifest_ver is not None, "El manifiesto no contiene la clave raíz '.'"

    # 2. Archivo de metadatos pyproject.toml
    pyproject_file = root_dir / "pyproject.toml"
    assert pyproject_file.exists(), "Falta el archivo pyproject.toml"
    pyproject_data = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
    project_ver = pyproject_data.get("project", {}).get("version")
    commitizen_ver = pyproject_data.get("tool", {}).get("commitizen", {}).get("version")

    # 3. Código fuente __init__.py
    source_ver = jame_firewall.__version__

    # 4. Formato SemVer 2.0.0
    semver_pattern = re.compile(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9_\-\.]+)?$")
    assert semver_pattern.match(source_ver), f"La versión {source_ver} no cumple SemVer 2.0.0"

    # 5. Aserción de Invarianza Estricta
    assert manifest_ver == project_ver == commitizen_ver == source_ver, (
        f"Desalineación crítica detectada: Manifest={manifest_ver}, Project={project_ver}, Commitizen={commitizen_ver}, Source={source_ver}"
    )


@pytest.mark.unit
def test_release_please_config_schema_and_package_alignment() -> None:
    """Verifica que release-please-config.json esté correctamente estructurado,

    con release-type 'python' y que 'src/jame_firewall/__init__.py' esté registrado en
    extra-files.
    """
    root_dir = Path(__file__).resolve().parent.parent.parent
    config_file = root_dir / "release-please-config.json"
    assert config_file.exists(), "Falta release-please-config.json"

    config_data = json.loads(config_file.read_text(encoding="utf-8"))
    root_pkg = config_data.get("packages", {}).get(".")
    assert root_pkg is not None, "No se encontró configuración para el paquete raíz '.'"
    assert root_pkg.get("release-type") == "python", "El release-type debe ser 'python'"
    assert root_pkg.get("package-name") == "JameFirewall", "El package-name debe ser 'JameFirewall'"

    extra_files = root_pkg.get("extra-files", [])
    assert "src/jame_firewall/__init__.py" in extra_files, (
        "src/jame_firewall/__init__.py debe estar registrado en extra-files de release-please"
    )
