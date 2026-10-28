"""Upload validation for Bayyina contracts. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass

class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors          # field name -> message; keys from: filename, content_type,
                                      # size_bytes, matter_id, first_bytes


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str      # "<32 hex chars>.<ext>", generated, never derived from the filename
    display_name: str     # the filename after NFC normalisation
    extension: str        # "pdf" or "docx", lowercase
    content_type: str
    size_bytes: int
    matter_id: str


def validate_upload(meta: dict) -> CleanUpload:
    """Check every field of `meta` and raise one ValidationError listing all failing fields."""
    raise NotImplementedError
"""Upload validation for Bayyina Guard."""



MAX_BYTES = 25 * 1024 * 1024

# Bidi control characters that are not allowed in filenames.
_BIDI_CONTROLS = frozenset(
    [
        "\u061c",
        "\u200e",
        "\u200f",
        *[chr(cp) for cp in range(0x202A, 0x202E + 1)],
        *[chr(cp) for cp in range(0x2066, 0x2069 + 1)],
    ]
)

_CONTENT_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

_MAGIC_BYTES = {
    "pdf": b"%PDF-",
    "docx": b"PK\x03\x04",
}

_MATTER_ID_RE = re.compile(r"\AMAT-\d{4}-\d{5}\Z")


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        self.errors = errors
        super().__init__(f"Validation failed: {errors}")


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str
    display_name: str
    extension: str
    content_type: str
    size_bytes: int
    matter_id: str


def _parse_filename(value) -> tuple[str | None, str | None, str | None]:
    """Return (display_name, extension, error). On error, display_name/extension are None."""
    if not isinstance(value, str):
        return None, None, "filename must be a string"

    normalized = unicodedata.normalize("NFC", value)

    length = len(normalized)
    if not (1 <= length <= 120):
        return None, None, "filename must be 1 to 120 characters"

    for ch in normalized:
        if unicodedata.category(ch) == "Cc":
            return None, None, "filename must not contain control characters"
        if ch in _BIDI_CONTROLS:
            return None, None, "filename must not contain bidi control characters"

    if "/" in normalized or "\\" in normalized:
        return None, None, "filename must not contain path separators"
    if ".." in normalized:
        return None, None, "filename must not contain '..'"
    if normalized.startswith("."):
        return None, None, "filename must not start with '.'"

    if "." not in normalized:
        return None, None, "filename must have a pdf or docx extension"

    stem, _, ext = normalized.rpartition(".")
    ext_lower = ext.lower()
    if ext_lower not in _CONTENT_TYPES:
        return None, None, "filename extension must be pdf or docx"
    if not stem.strip():
        return None, None, "filename must have a name before the extension"

    return normalized, ext_lower, None


def validate_upload(meta: dict) -> CleanUpload:
    errors: dict[str, str] = {}

    display_name, extension, filename_err = _parse_filename(meta.get("filename"))
    if filename_err is not None:
        errors["filename"] = filename_err

    # content_type
    content_type_value = meta.get("content_type")
    if filename_err is None:
        expected_ct = _CONTENT_TYPES[extension]
        if content_type_value != expected_ct:
            errors["content_type"] = f"content_type must be {expected_ct!r}"
    else:
        if not isinstance(content_type_value, str):
            errors["content_type"] = "content_type must be a string"

    # first_bytes
    first_bytes_value = meta.get("first_bytes")
    if filename_err is None:
        if not isinstance(first_bytes_value, bytes):
            errors["first_bytes"] = "first_bytes must be bytes"
        elif not first_bytes_value.startswith(_MAGIC_BYTES[extension]):
            errors["first_bytes"] = (
                f"first_bytes must start with {_MAGIC_BYTES[extension]!r}"
            )
    else:
        if not isinstance(first_bytes_value, bytes):
            errors["first_bytes"] = "first_bytes must be bytes"

    # size_bytes
    size_value = meta.get("size_bytes")
    if (
        isinstance(size_value, bool)
        or not isinstance(size_value, int)
        or not (1 <= size_value <= MAX_BYTES)
    ):
        errors["size_bytes"] = f"size_bytes must be an int between 1 and {MAX_BYTES}"

    # matter_id
    matter_value = meta.get("matter_id")
    if not isinstance(matter_value, str) or not _MATTER_ID_RE.match(matter_value):
        errors["matter_id"] = "matter_id must match MAT-####-#####"

    if errors:
        raise ValidationError(errors)

    # Type checkers: values are guaranteed by the checks above.
    stored_name = f"{uuid.uuid4().hex}.{extension}"
    return CleanUpload(
        stored_name=stored_name,
        display_name=display_name,
        extension=extension,
        content_type=_CONTENT_TYPES[extension],
        size_bytes=size_value,
        matter_id=matter_value,
    )