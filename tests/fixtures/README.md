# IDAPython 8.0 reference inventory

`idapython-8.0-api_contents3.txt` is the unmodified official SWIG function
inventory from the "IDAPython for IDA 8.0" commit:

- Commit: `023c5ba53ca91c730d39539c2c50778ac8e5cd87`
- Source: https://github.com/idapython/src/blob/023c5ba53ca91c730d39539c2c50778ac8e5cd87/api_contents3.txt
- SHA-256: `fea242fa9f0b2afaee1c9e2a6799db5908231b390303c29dabce0509c589d89e`
- License: `IDAPYTHON-COPYING.txt`, copied from the same commit's `COPYING.txt`.

The inventory helped identify record renames and missing type methods. It
lists native wrapper functions, not all Python helpers or SDK constants.
Its absence of a symbol is therefore not a universal capability test.
It does not provide an IDAPython runtime.
