from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class FileClassification:
    category: str
    language: str


SOURCE_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
}

CONFIG_LANGUAGES = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "conf",
    ".env": "env",
}

DOC_LANGUAGES = {
    ".md": "markdown",
    ".rst": "rst",
    ".txt": "text",
}

DATA_LANGUAGES = {
    ".csv": "csv",
    ".tsv": "tsv",
    ".xml": "xml",
}

TEST_PATH_TOKENS = {
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
}

TEST_FILE_MARKERS = (
    ".test.",
    ".spec.",
    "_test.",
    "-test.",
    "test_",
)

CONFIG_FILENAMES = {
    ".env",
    ".env.local",
    ".env.example",
    ".env.development",
    ".env.production",
    ".env.test",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}

GENERATED_MARKERS = (
    ".min.js",
    ".min.css",
    ".bundle.js",
)


def classify_file(path: str) -> FileClassification:
    normalized = path.replace("\\", "/")
    pure_path = PurePosixPath(normalized)
    name = pure_path.name.lower()
    ext = pure_path.suffix.lower()
    parts = [part.lower() for part in pure_path.parts]

    if any(token in parts for token in TEST_PATH_TOKENS) or any(marker in name for marker in TEST_FILE_MARKERS):
        language = SOURCE_LANGUAGES.get(ext, "unknown")
        return FileClassification(category="test", language=language)

    if name in CONFIG_FILENAMES:
        language = CONFIG_LANGUAGES.get(ext, "env" if name.startswith(".env") else "config")
        return FileClassification(category="config", language=language)

    if any(name.endswith(marker) for marker in GENERATED_MARKERS):
        language = SOURCE_LANGUAGES.get(ext, "unknown")
        return FileClassification(category="generated", language=language)

    if ext in SOURCE_LANGUAGES:
        return FileClassification(category="source", language=SOURCE_LANGUAGES[ext])

    if ext in CONFIG_LANGUAGES:
        return FileClassification(category="config", language=CONFIG_LANGUAGES[ext])

    if ext in DOC_LANGUAGES:
        return FileClassification(category="docs", language=DOC_LANGUAGES[ext])

    if ext in DATA_LANGUAGES:
        return FileClassification(category="data", language=DATA_LANGUAGES[ext])

    return FileClassification(category="other", language="unknown")
