"""Contract tests for the canonical Windows application icon."""

from pathlib import Path

from PIL import Image

from jame_firewall.presentation import constants as C

EXPECTED_ICON_SIZES = {
    (16, 16),
    (24, 24),
    (32, 32),
    (48, 48),
    (64, 64),
    (128, 128),
    (256, 256),
}


def test_canonical_icon_resource_exists_and_is_multiresolution() -> None:
    """The packaged icon must expose every Windows shell resolution we support."""
    repository_root = Path(__file__).resolve().parents[2]
    icon_path = repository_root / C.APP_ICON_RESOURCE

    assert icon_path.is_file()

    with Image.open(icon_path) as icon:
        ico = getattr(icon, "ico", None)
        assert ico is not None
        assert set(ico.sizes()) == EXPECTED_ICON_SIZES
