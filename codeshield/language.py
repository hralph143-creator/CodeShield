from pathlib import Path


EXTENSION_LANGUAGES = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".r": "r",
    ".rs": "rust",
    ".env": "config",
    ".ini": "config",
    ".conf": "config",
    ".cfg": "config",
    ".properties": "config",
    ".yaml": "config",
    ".yml": "config",
    ".json": "config",
    ".xml": "config",
    ".toml": "config",
}

SPECIAL_FILENAMES = {
    ".env": "config",
}


def file_extension(path: Path) -> str:
    name = path.name.lower()
    return name if name in SPECIAL_FILENAMES else path.suffix.lower()


def detect_language(path: Path) -> str | None:
    name = path.name.lower()
    return SPECIAL_FILENAMES.get(name) or EXTENSION_LANGUAGES.get(path.suffix.lower())
