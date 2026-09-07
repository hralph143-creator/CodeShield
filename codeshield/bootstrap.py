from dataclasses import dataclass
import logging

from codeshield.config import AppConfig, ConfigStore
from codeshield.database import Database
from codeshield.logging_setup import configure_logging


@dataclass(slots=True)
class Runtime:
    config: AppConfig
    config_store: ConfigStore
    database: Database

    def create_scanner(self, config: AppConfig | None = None):
        from codeshield.scanner import ProjectScanner

        return ProjectScanner(
            config or self.config,
            additional_rules=self.database.active_custom_rules(),
            disabled_rule_ids=self.database.disabled_builtin_rule_ids(),
            whitelist_matcher=self.database.is_whitelisted,
        )


def build_runtime() -> Runtime:
    config_store = ConfigStore()
    log_path = configure_logging(config_store.prepare_data_dir())
    logging.getLogger(__name__).info("应用启动 log=%s", log_path)
    config = config_store.load()
    database = Database(config_store.data_dir / "codeshield.db")
    try:
        database.initialize()
    except Exception:
        logging.getLogger(__name__).exception("DB-001 数据库初始化失败")
        raise
    return Runtime(config=config, config_store=config_store, database=database)
