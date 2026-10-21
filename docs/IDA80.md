# IDA 8.0 compatibility fork

## Current status

The target is **IDA Pro 8.0 with IDAPython**. IDA Freeware 8.0 was used
as a reference binary; this project does not supply its missing IDAPython
plugin. The Python MCP entry point cannot run inside that Freeware installation.

IDA 8.0 uses IDAPython with Python 3.10 or newer. The MCP server runs
in a separate Python 3.11+ environment. For automatic background loading,
configure `IDA_NEXUS_IDAT` as described below. The server then starts a console
IDA worker; opening the input in the GUI is no longer required. Leaving this
variable unset preserves GUI attachment and the existing IDA 9.4+ idalib path.

The user confirmed IDA 8.0 GUI database registration on the other computer.
**The new console backend still needs end-to-end validation on actual IDA 8.0.**
It has been tested with a real IDA 9.5 console host, without idalib or a GUI.
Local mock tests establish specific SDK contracts; they are not an IDA 8 emulator.

## Automatic background loading (ida80.4)

Keep the modified repository on the same computer as IDA and run `uv sync --locked`.
In Codex's existing MCP configuration, add:

```toml
[mcp_servers.ida80.env]
IDA_NEXUS_IDAT = 'C:\Program Files\IDA Pro 8.0'
```

Restart the Agent/MCP connection. Its `command` and `args` must still run this
local checkout, for example `uv --directory D:\code\ida-mcp run --locked ida-mcp stdio`.
For clients using JSON, set the same variable in that server's `env` object.
No GUI plugin installation is needed for the console worker; the launcher loads
the local dependency forks directly into IDAPython.

The directory selects `idat64.exe` first for new `.i64` databases and `idat.exe`
for existing `.idb` databases. A full console executable path is also accepted.
The executable must be present and have working IDAPython and an IDA Pro license.
An already registered GUI database is reused if it matches the requested file.

Now call `open_database(path="D:\\samples\\program.exe")`. The result should
contain `backend: "idat"` when a worker is spawned. `execute_python` waits for
analysis through the existing MCP barrier. Several clients share one worker for
the same database; different databases use separate processes. Final lease
release saves the database and exits the worker. Normal `close_database` does
not close unrelated GUI instances.

To verify without opening any GUI, copy a small executable to a fresh directory
(with no existing database), then run:

```powershell
uv run python scripts/verify_ida.py `
  --database 'D:\samples\console-test.exe' `
  --idat 'C:\Program Files\IDA Pro 8.0' `
  --expect-version 8.0 --headless-only --output ida80-headless-report.json

uv run python scripts/verify_idat_lifecycle.py `
  --binary 'D:\samples\console-test.exe' `
  --idat 'C:\Program Files\IDA Pro 8.0' `
  --expect-version 8.0 --output ida80-lifecycle-report.json
```

The second script makes disposable copies and checks sharing, independent
workers, cancellation by timeout, saving/reopening, discarding changes, and idle
shutdown. Reports and logs identify the actual kernel version. Passing on IDA
9.5 does not substitute for the IDA 8.0 run.

Implementation: the existing idalib worker imports `idapro`, opens a database
with `Database.open()`, and uses `ida_kernwin.serve()` (9.4+) for main-thread
dispatch. The new worker starts `idat64 -A -a -S... input`, loads the database
through IDA's normal loader, and attaches with `Database.open()` inside that
process. A Python queue dispatches every operation on the script's main thread;
the existing Nexus HTTP server, authenticated registry, lease watchdog, and
analysis scheduler are reused. Analysis advances in bounded native steps.
Windows uses `CREATE_NO_WINDOW`; no GUI window or manual file-open step is used.
See the official [command-line guide](https://hex-rays.com/blog/igor-tip-of-the-week-07-ida-command-line-options-cheatsheet).

`-B` is deliberately not used: it exits after generating assembly instead of
keeping a service alive. The console backend reserves `-S` for the service and
rejects `script_file`, `run_debugger`, and named `debug_flags` before launching;
use `execute_python` for scripts and numeric masks for debug flags. Other loader
options use the existing open options, with import-only switches omitted when
reopening an IDB. Startup diagnostics are under the Nexus `logs` directory;
failed or timed-out direct console starts are terminated. The worker uses the
Python runtime configured in IDA, not the MCP virtual environment.

Local validation for this revision:

- Root suite: 196 tests and 8 subtests; Python 3.10 compatibility subset: 52 tests.
- Nexus runtime/lifecycle suite: 362 passed, 4 skipped. Its original release
  version test was excluded because it rejects local `+ida80` version suffixes;
  the root version/dependency checker passes. Real idalib tests use the explicit
  smoke run below instead of the upstream environment-specific E2E suite.
- [Fresh console MCP run on IDA 9.5](validation/ida95-idat-smoke.json).
- [Console lifecycle run on IDA 9.5](validation/ida95-idat-lifecycle.json).
- [Original idalib MCP regression on IDA 9.5](validation/ida95-idalib-regression.json).
- Root Ruff, formatting, type, and version checks pass.

These reports are local IDA 9.5 evidence, not confirmation of IDA 8.0 console behavior.

The `ida80.2` revision fixes the reported IDA 8 startup failure
`cannot import name 'ea_t' from 'ida_idaapi'`. Address annotations now use
a package-local `int` alias, including the hook definitions evaluated at
import time. Startup failures also print a complete traceback.

The `ida80.3` revision fixes `NameError: name 'CODE' is not defined` during
the import of `xrefs.py`. Its xref filters use the legacy `XREF_FAR` flag
when `XREF_NOFLOW` is absent. On SDKs without `XREF_CODE`, code-only
selection happens in Python; the private filter bit is never passed to
the native iterator. Optional symbolic/obsolete reference kinds no
longer break classification when the SDK does not define them.

When updating an existing install, close IDA, run `git pull --ff-only`,
then repeat `uv sync --locked` and `uv run python scripts/install_ida80.py`.
Restart IDA afterwards. Pulling the repository alone does not replace
the dependency copies already installed in its plugin directory.

## Install on the IDA 8 computer

Copy this entire checkout, including `vendor`, to the other computer.
Keep IDA closed during installation. Install `uv` and an external
Python 3.11+ interpreter first.

From the checkout directory:

```powershell
uv sync --locked
uv run python scripts/install_ida80.py
```

The installer writes:

```text
<IDAUSR>/plugins/ida_mcp_plugin.py
<IDAUSR>/plugins/ida_mcp_deps/
```

On Windows, the default is `%APPDATA%\Hex-Rays\IDA Pro`. `IDAUSR` is honored,
including its first directory if it contains multiple entries. An explicit
destination is also supported:

```powershell
uv run python scripts/install_ida80.py --plugins-dir "C:\path\to\IDA-user\plugins"
```

The flat entry point works with IDA 8 plugin discovery. Its adjacent
dependency directory contains the patched pure-Python Nexus/Domain packages,
`packaging` and `typing_extensions`; it does not install idalib into IDA 8.
Existing files are backed up in `<IDAUSR>/ida-mcp-backups/`.
Do not also load an upstream Nexus/MCP provider in the same IDA process;
restart IDA after changing dependency versions.

In IDA's Python console, check `sys.version`. If it is older than 3.10,
select a compatible Python 3.10 interpreter using that IDA installation's
`idapyswitch` utility. Installing Python packages in the external MCP
environment does not change the Python interpreter embedded in IDA.

Start IDA and open a disposable test binary. The Output window should show:

```text
[ida-mcp] Database registered successfully!
```

Configure the MCP client to run this checkout, replacing the directory below:

```json
{
  "mcpServers": {
    "ida": {
      "command": "uv",
      "args": [
        "--directory", "D:\\code\\ida-mcp",
        "run", "--locked", "ida-mcp", "stdio", "--agent=my-agent"
      ]
    }
  }
}
```

Use the same Windows user and `IDAUSR` / `IDA_NEXUS_STATE_DIR` values for
IDA and the MCP process. The service remains local and uses Nexus's existing
authenticated transport and lease handling.

The two modified dependency versions are pinned with local version suffixes.
Installing the root package with plain `pip install .` alone is insufficient;
`uv sync` selects the local source packages. To use pip, explicitly install
all three packages together:

```powershell
python -m pip install ./vendor/ida-domain ./vendor/ida-nexus .
```

## Verify the real IDA 8 runtime

Use a copy of a small executable, for example a copy of Windows `where.exe`.
Open the copy in IDA 8.0, let analysis finish, and leave IDA responsive.

In a terminal at this checkout, substitute the **exact binary or database path
reported by `list_databases`**:

```powershell
uv run python scripts/verify_ida.py `
  --database "D:\samples\where-copy.exe" `
  --expect-version 8.0 `
  --gui-only `
  --output ida80-report.json
```

The verifier starts the actual MCP stdio server and checks all six tools.
It verifies the kernel version before its analysis probe; an IDA 9 process
cannot satisfy `--expect-version 8.0`. It checks functions, disassembly,
byte search, segments, strings, xrefs, named/numbered types and declaration
parsing. It also reads structure-offset paths for the first instruction's
operands. It writes and restores one comment, tests pseudocode when a
decompiler is available, saves the test database and releases the lease.
The GUI remains open.

Both success and execution failures produce a JSON report. A missing GUI
registration is an error in `--gui-only` mode. This test should be performed
on a disposable sample because it exercises database saving.

If IDA reports an import error before registration, copy the complete Output
window traceback as well. `ida80-report.json` and that traceback are the
inputs needed to continue the remaining real-runtime compatibility fixes.

## Adaptations

- `ida-nexus` accepts IDA 8+ for GUI services while retaining the IDA 9.4+
  requirement for idalib workers.
- GUI detection no longer requires the newer `IDA_IS_INTERACTIVE` environment
  variable and explicitly excludes idalib.
- Nexus's Python 3.11 `Self` imports use the Python 3.10 backport.
- Domain tolerates the absent `is_ida_library()` API in IDA 8.
- Address annotations use a local `ea_t = int` alias; IDAPython 8 is not
  required to export the newer `ida_idaapi.ea_t` name.
- Code/data/flow xref filters support both old and new SDK flags. Applying
  `NOFLOW` alone also preserves its native flag instead of resetting it.
- IDAPython 8's `udt_member_t` and `enum_member_t` get local aliases for
  the newer record names; the SDK modules are not monkeypatched.
- Byte search uses IDA 8's compiled-pattern overload when `find_bytes`
  is absent. The old raw overload's fifth argument is a direction step,
  not the length expected by newer wrappers. Both first-match and
  all-matches public search methods use this fallback.
- FLIRT support no longer imports the absent `ida_undo` module at startup.
  Ordinary signature application remains available.
- Type enumeration uses the older `tinfo_t` lookup APIs and handles the
  disabled-ordinal `0xFFFFFFFF` sentinel.
- Function argument enumeration uses `get_func_details` and its native
  vector, without requiring the newer `iter_func` convenience method.
- Older enum/type metadata predicates and basic structure/union/enum
  builders have fallbacks.
- Structure operand formatting uses IDB structure/member IDs on IDA 8,
  with the native `tid_array` and output-pointer signatures. Structure
  names come from `ida_struct`; IDA 9 keeps its unified type-ID APIs.
- SDK enum members are exposed only when the running SDK provides their
  constants. No invented numeric SDK constants are supplied.

## Known API boundaries and remaining verification

Features introduced after IDA 8 do not acquire native support merely by
lowering a version requirement. In particular:

- Unified type/member-TID cross-reference conveniences require IDA 9.
  IDA 8's ordinary address xrefs and native `ida_struct` / `ida_enum` APIs
  remain available through `execute_python`.
- Type-level comment conveniences are gated to IDA 8.4+; ordinary address
  and function comments use the existing SDK APIs.
- Enabling numbered types in an external TIL cannot be synthesized through
  IDAPython 8's exported API. Local IDB type ordinals are supported.
- FLIRT `probe_only` requires the `ida_undo` module, which IDAPython 8
  does not provide. It raises before applying signatures on this SDK.
  Ordinary application works, but `FileInfo.matches` and `FileInfo.functions`
  are `None` on SDKs without the `idasgn_matched_ea` notification. This means
  the match details are unavailable, rather than claiming no functions matched.
- SDKs without `op_based_stroff` cannot infer a structure offset from an
  instance address through `display_based_struct_offset`. Use
  `display_struct_offset` with an explicit IDB structure ID and delta.
- The legacy enum builder rejects bitmask enums that require explicit mask
  groups. Use native `ida_enum` or a declaration for those cases.
- If the SDK recalculates a structure layout and does not preserve requested
  explicit offsets, the fallback raises an error instead of returning a
  misleading layout. A declaration with padding can express such layouts.
- Some advanced Domain operations still rely on newer SDK methods. The
  real IDA 8 import/execution report is needed to audit remaining paths.

Do not interpret the package version/manifest or the local test count as a
claim that every modern Domain operation works in IDA 8.

## Validation performed locally

- Main project tests, including strict compatibility doubles and installer
  rollback checks.
- The compatibility tests also run using a real CPython 3.10 interpreter.
- Selected upstream Nexus runtime, reference and public API tests.
- A real IDA 9.5 MCP stdio smoke test using both local dependency forks:
  103 functions, 8 segments, 138 strings, 63 named and numbered types,
  pseudocode output, restored comment, save and close.
- A staged GUI dependency installation, without changing the user's active
  IDA installation.

## Reference evidence

The source API inventory is from the official
[IDAPython for IDA 8.0 commit](https://github.com/idapython/src/commit/023c5ba53ca91c730d39539c2c50778ac8e5cd87).
Its [byte-search wrapper](https://github.com/idapython/src/blob/023c5ba53ca91c730d39539c2c50778ac8e5cd87/pywraps/py_bytes.hpp)
and [type wrapper exclusions](https://github.com/idapython/src/blob/023c5ba53ca91c730d39539c2c50778ac8e5cd87/swig/typeinf.i)
were checked directly.
The commit's [complete source tree](https://api.github.com/repos/idapython/src/git/trees/023c5ba53ca91c730d39539c2c50778ac8e5cd87?recursive=1)
was also checked against SDK modules imported by the two forks: `ida_undo`
has no wrapper or Python module in that revision. A regression test imports
the FLIRT module with `ida_undo` unavailable, applies a signature through
SDK doubles, and checks that unsupported probing has no side effects.
The official 8.0 [`idc.op_stroff` implementation](https://github.com/idapython/src/blob/023c5ba53ca91c730d39539c2c50778ac8e5cd87/python/idc.py#L949)
provides the native path-array calling convention. The old four-argument
`get_stroff_path` form is also documented in the
[8.4 wrapper reference](https://python.docs.hex-rays.com/8.4/dd/dca/namespaceida__bytes.html).
Its pointer call was checked against the backwards-compatible IDA 9.5
wrapper; this does not establish its behavior in a real IDA 8 process.

The connected IDA MCP (analysis kernel 9.5) analyzed the local
`D:\Program Files\IDA Freeware 8.0\ida64.dll`. Reference findings:

| Target address | Function | Finding |
|---|---|---|
| `0x1000C6CE0` | `init_plugins` | Plugin initialization exists; this alone does not establish IDAPython availability. |
| `0x1001D8E60` | `install_extlang` | External-language registration exists; no Python binding is supplied by this function. |
| `0x100107FB0` | `bin_search` | Legacy search adapter constructs compiled patterns. |
| `0x1001081C0` | `bin_search2` | Compiled-pattern search delegates to `bin_search3`. |
| exported symbol | `alloc_type_ordinals` | A zero quantity returns 0 immediately; it cannot enable ordinal support. |
| exported symbol | `get_ordinal_qty` | Disabled ordinal support returns `0xFFFFFFFF`. |

These are observations about the target 8.0 binary, not evidence that the
patched Python packages ran inside IDA 8.0.
