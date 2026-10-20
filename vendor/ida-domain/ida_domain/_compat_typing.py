"""Python annotation aliases independent of IDAPython's SDK version."""

from typing import TypeAlias

# Newer ida_idaapi modules export this exact alias; IDAPython 8 does not.
# An effective address is a Python int, including BADADDR. Do not patch the
# SDK module or replace it with a bounded ctypes integer.
ea_t: TypeAlias = int
