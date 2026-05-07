from __future__ import annotations

from pathlib import Path

import typer

from hunter.logging import configure_logging
from hunter.orchestration.scan_runner import run_scan
from hunter.settings import HunterSettings

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.command("scan")
def scan(
    plugin_path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True, help="Path to WP plugin"),
    config: Path | None = typer.Option(None, "--config", help="YAML config override"),
    output_root: Path | None = typer.Option(None, "--output-root", help="Override output directory root"),
    agents: bool = typer.Option(False, "--agents/--no-agents", help="Enable LangGraph agent phase"),
) -> None:
    """Run deterministic static analysis pipeline on a local plugin directory."""
    settings = HunterSettings.load(config)
    if output_root is not None:
        settings = settings.model_copy(update={"output_root": output_root})
    settings = settings.model_copy(update={"agents_enabled": agents})
    configure_logging(settings.log_level, json_logs=True)
    result = run_scan(plugin_path, settings)
    typer.echo(f"scan_id={result.scan_id}")
    typer.echo(f"output_dir={result.output_dir}")
    typer.echo(f"snapshot_id={result.snapshot_id}")
    typer.echo(f"graph_integrity_ok={result.graph_integrity_ok}")
    if result.errors:
        for e in result.errors:
            typer.echo(f"warning: {e}", err=True)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
