import sqlite3

c = sqlite3.connect("workspaces/data/hunter.db")
for r in c.execute(
    "select id, plugin_slug, status, findings_count, source_type, source_label, "
    "output_dir, error_message, started_at, finished_at "
    "from scans where id='de7e1bdfac17451fa350366caf344f2c'"
):
    for k, v in zip(
        [
            "id",
            "plugin_slug",
            "status",
            "findings_count",
            "source_type",
            "source_label",
            "output_dir",
            "error_message",
            "started_at",
            "finished_at",
        ],
        r,
    ):
        print(f"{k:>16}: {v}")
