from dataclasses import dataclass

from codeshield.config import AppConfig, ConfigStore
from codeshield.database import Database


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
    config = config_store.load()
    database = Database(config_store.data_dir / "codeshield.db")
    database.initialize()
    return Runtime(config=config, config_store=config_store, database=database)
