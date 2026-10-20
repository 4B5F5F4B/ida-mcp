# Local compatibility forks

These directories contain upstream source distributions, downloaded from
PyPI and verified against the original repository's `uv.lock`.
Keep their original license files with redistributed copies.

| Package | Upstream version | Source SHA-256 | Local version |
|---|---|---|---|
| ida-nexus | 0.13.4 | `850fd732f478787306b50d4639b63edc5e510978d089d2e552be7e27655babb0` | 0.13.4+ida80.3 |
| ida-domain | 0.5.1 | `c49f2c417047d882e954f651b50a709a3f27903b33ba533b794aa54d6536d16f` | 0.5.1+ida80.3 |

Sources:

- [ida-nexus source archive](https://files.pythonhosted.org/packages/f9/87/834d0c5b6bdaadcb477822eb0755ebfa57a1543c8809baf6f893ffc2b5d2/ida_nexus-0.13.4.tar.gz)
- [ida-domain source archive](https://files.pythonhosted.org/packages/80/34/be087d3ea1c3a6573e0660cb5b40f0c4ade9ae5772cf1c5d98d52472d28b/ida_domain-0.5.1.tar.gz)

See [the compatibility notes](../docs/IDA80.md) for the changes, evidence,
installation procedure and outstanding real IDA 8 verification.

The root `pyproject.toml` pins these forks and maps them through
`tool.uv.sources`. The GUI installer builds both local packages and installs
their pure-Python dependencies into a private plugin directory. `idapro` is
an optional Domain extra used by the external server for modern idalib
workers; it is not an IDA 8 runtime.
