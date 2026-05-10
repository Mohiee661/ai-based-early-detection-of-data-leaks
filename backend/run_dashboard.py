from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def log(level: str, message: str) -> None:
    print(f"[{level}] {message}")


def resolve_python() -> Path:
    project_root = Path(__file__).resolve().parent
    venv_python = project_root / "venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        return venv_python
    return Path(sys.executable)


def main() -> int:
    project_root = Path(__file__).resolve().parent
    dashboard_path = project_root / "dashboard.py"
    python_executable = resolve_python()

    if not dashboard_path.exists():
        log("ERROR", f"Dashboard file not found: {dashboard_path}")
        return 1

    log("INFO", "Starting DarkShield dashboard...")

    # On Windows, `python -m streamlit` is more reliable than the bare
    # `streamlit` command because it uses the selected interpreter directly
    # instead of depending on a PATH-discoverable launcher script.
    #
    # Virtual environments matter here because they keep this project's
    # dependencies isolated, so we launch Streamlit with the `venv` Python
    # whenever it is available.
    command = [
        str(python_executable),
        "-m",
        "streamlit",
        "run",
        str(dashboard_path),
    ]

    try:
        subprocess.run(command, cwd=project_root, check=True)
        log("SUCCESS", "DarkShield dashboard exited cleanly.")
        return 0
    except FileNotFoundError:
        log("ERROR", f"Python executable not found: {python_executable}")
        log("ERROR", "Make sure the project's virtual environment exists.")
        return 1
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 1:
            log("ERROR", "Streamlit could not be launched with the selected Python interpreter.")
            log("ERROR", "Install it in the virtual environment with: venv\\Scripts\\python.exe -m pip install streamlit")
        else:
            log("ERROR", f"Dashboard process exited with code {exc.returncode}.")
        return exc.returncode
    except Exception as exc:
        log("ERROR", f"Unexpected error while starting the dashboard: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
