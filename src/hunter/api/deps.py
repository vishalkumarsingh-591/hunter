from __future__ import annotations

from functools import lru_cache

from hunter.logging import configure_logging
from hunter.persistence.database import init_db
from hunter.settings import HunterSettings


@lru_cache
def get_settings() -> HunterSettings:
    settings = HunterSettings.load()
    configure_logging(settings.log_level, json_logs=True)
    if not settings.database_url:
        data_dir = settings.workspace_root / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        db_path = data_dir / "hunter.db"
        settings = settings.model_copy(update={"database_url": f"sqlite:///{db_path.as_posix()}"})
    init_db(settings.database_url)
    return settings
