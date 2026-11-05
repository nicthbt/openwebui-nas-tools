# AGENTS.md

## What this repo is

Open WebUI **tool**, not a standalone app. It runs inside the Open WebUI server (`src/common/base.py` imports `open_webui.*` internals), so the code cannot be run or tested outside Open WebUI.

- `src/` — real source. `src/main.py` defines the `Tools` class exposed to Open WebUI.
- `openwebui_nas_tools.py` — generated single-file distribution, committed to git. Never edit by hand; users paste its content into Open WebUI's tool editor.
- `build.py` — stdlib-only bundler that inlines `src/` imports into the distribution file.

## Build

After changing anything under `src/`, regenerate the committed artifact (it must stay in sync with `src/`):

```sh
.venv/bin/python build.py --output openwebui_nas_tools.py
```

`build.py` needs only the standard library; the VS Code default build task uses `.venv/bin/python` (Python 3.12).

## Bundler constraints (build fails if violated)

- Local imports must be top-level `from src.module import Name`. No `import src.module`, no `as` aliases, no wildcards, no function-level imports.
- One statement per line in bundled modules.
- Duplicate module-level globals must have identical declarations (`log = logging.getLogger(__name__)` repeated in every module is fine).

## Tool metadata

The docstring header of `src/main.py` is the Open WebUI tool metadata (`version`, `requirements`, `required_open_webui_version`, …). Bump `version:` there; keep `requirements:` in sync with the README.

## Verification

No tests, lint, typecheck, or CI exist in this repo. Verification = a successful build (it compiles the output) plus Ruff formatting (VS Code format-on-save; no ruff config file, so defaults apply).

## Architecture notes

- `@custom_tool` (`src/common/decorators.py`) mixes `CustomTool` (`src/common/base.py`) into `Tools`, providing valves, per-call context via `ContextVar`, and the Open WebUI file/RAG integration.
- Tool methods are wrapped by `with_context`: it connects, sets the session context, and catches exceptions, returning `{"error": ...}` JSON instead of raising.
- Protocol handlers (`api`/`sftp`/`samba`) are selected by `_get_handlers()` in `main.py`; only Synology FileStation and Open Terminal have dedicated client classes in `src/clients/`.
