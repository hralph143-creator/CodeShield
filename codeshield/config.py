from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


DEFAULT_EXTENSIONS = [
    ".py", ".java", ".js", ".jsx", ".ts", ".tsx", ".c", ".h",
    ".cpp", ".hpp", ".r", ".rs", ".env", ".ini", ".conf", ".cfg",
    ".properties", ".yaml", ".yml", ".json", ".xml", ".toml",
]

SCAN_MODES = ("standard", "full", "custom")
SCAN_MODE_LABELS = {
    "standard": "标准扫描",
    "full": "完整扫描",
    "custom": "自定义扫描",
}

STANDARD_IGNORED_DIRS = [
    ".git", ".svn", ".idea", ".vscode", "node_modules", "dist", "build",
    "release", "target", "venv", ".venv", "__pycache__", "coverage", ".cache",
]
FULL_IGNORED_DIRS = [".git", ".svn", "__pycache__", ".cache"]
DEFAULT_IGNORED_DIRS = STANDARD_IGNORED_DIRS

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AppConfig:
    scan_mode: str = "standard"
    max_file_size_mb: int = 5
    detect_personal_info: bool = True
    included_extensions: list[str] = field(default_factory=lambda: DEFAULT_EXTENSIONS.copy())
    ignored_dirs: list[str] = field(default_factory=lambda: DEFAULT_IGNORED_DIRS.copy())
    min_entropy_length: int = 16
    entropy_threshold: float = 3.8

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> "AppConfig":
        defaults = cls()
        scan_mode = values.get("scan_mode", defaults.scan_mode)
        size = values.get("max_file_size_mb", defaults.max_file_size_mb)
        personal_info = values.get("detect_personal_info", defaults.detect_personal_info)
        extensions = values.get("included_extensions", defaults.included_extensions)
        ignored_dirs = values.get("ignored_dirs", defaults.ignored_dirs)
        min_entropy_length = values.get("min_entropy_length", defaults.min_entropy_length)
        entropy_threshold = values.get("entropy_threshold", defaults.entropy_threshold)

        if not isinstance(scan_mode, str) or scan_mode not in SCAN_MODES:
            scan_mode = defaults.scan_mode
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 100:
            size = defaults.max_file_size_mb
        if not isinstance(personal_info, bool):
            personal_info = defaults.detect_personal_info
        if not isinstance(extensions, list) or not all(isinstance(item, str) for item in extensions):
            extensions = defaults.included_extensions
        if not isinstance(ignored_dirs, list) or not all(isinstance(item, str) for item in ignored_dirs):
            ignored_dirs = defaults.ignored_dirs
        if (
            isinstance(min_entropy_length, bool)
            or not isinstance(min_entropy_length, int)
            or not 4 <= min_entropy_length <= 128
        ):
            min_entropy_length = defaults.min_entropy_length
        if (
            isinstance(entropy_threshold, bool)
            or not isinstance(entropy_threshold, (int, float))
            or not 0 <= entropy_threshold <= 8
        ):
            entropy_threshold = defaults.entropy_threshold

        return cls(
            scan_mode=scan_mode,
            max_file_size_mb=size,
            detect_personal_info=personal_info,
            included_extensions=list(extensions),
            ignored_dirs=list(ignored_dirs),
            min_entropy_length=min_entropy_length,
            entropy_threshold=float(entropy_threshold),
        )


class ConfigStore:
    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or self._default_data_dir()
        self.path = self.data_dir / "settings.json"

    @staticmethod
    def _default_data_dir() -> Path:
        # 安装版目录可能不可写，配置和数据库统一放到当前用户的数据目录。
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "CodeShield" if base else Path.cwd() / ".codeshield_data"

    def load(self) -> AppConfig:
        self._ensure_data_dir()
        if not self.path.exists():
            config = AppConfig()
            self.save(config)
            return config

        try:
            values = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            logger.warning("配置读取失败，已使用默认设置：%s", type(exc).__name__)
            return AppConfig()
        return AppConfig.from_dict(values) if isinstance(values, dict) else AppConfig()

    def prepare_data_dir(self) -> Path:
        self._ensure_data_dir()
        return self.data_dir

    def save(self, config: AppConfig) -> None:
        self._ensure_data_dir()
        temporary_path = self.path.with_suffix(".tmp")
        temporary_path.write_text(
            json.dumps(asdict(config), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary_path.replace(self.path)

    def _ensure_data_dir(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            # 受限电脑可能禁写用户数据目录，便携运行时回退到程序工作目录。
            self.data_dir = Path.cwd() / ".codeshield_data"
            self.path = self.data_dir / "settings.json"
            self.data_dir.mkdir(parents=True, exist_ok=True)
