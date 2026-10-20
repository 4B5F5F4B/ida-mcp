"""Runtime detection shared by IDA 8 GUI and modern idalib hosts."""

from __future__ import annotations


def is_ida_library() -> bool:
    import ida_kernwin

    # idalib did not exist in IDA 8. A missing probe inside IDAPython means
    # a GUI/text IDA process, not a request to load a second kernel.
    probe = getattr(ida_kernwin, 'is_ida_library', None)
    return bool(probe(None, 0, None)) if probe is not None else False
