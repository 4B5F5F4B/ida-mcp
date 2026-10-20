"""Byte search across the IDA 8 and IDA 9 IDAPython signatures."""

from __future__ import annotations


def find_bytes(pattern: bytes, start_ea: int, end_ea: int) -> int:
    import ida_bytes

    modern = getattr(ida_bytes, 'find_bytes', None)
    if modern is not None:
        return modern(pattern, start_ea, None, end_ea)
    # Use the stable compiled-pattern overload. IDA 8.0's six-argument raw
    # overload takes a direction step where newer versions take a length!
    patterns = ida_bytes.compiled_binpat_vec_t()
    error = ida_bytes.parse_binpat_str(patterns, start_ea, pattern.hex(' '), 16)
    if error is False or (isinstance(error, str) and error):
        raise ValueError(f'Cannot compile byte pattern: {error}')
    result = ida_bytes.bin_search(
        start_ea, end_ea, patterns,
        ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
    )
    return result[0] if isinstance(result, tuple) else result
