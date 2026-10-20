"""Structure operand adapters for the pre-9 IDB structure model."""

from __future__ import annotations

import ida_bytes
import ida_kernwin
import ida_name
import ida_typeinf


def _legacy_structs() -> bool:
    return int(ida_kernwin.get_kernel_version().split('.')[0]) < 9


def _tid_array(path: list[int]):
    import ida_pro

    result = ida_pro.tid_array(len(path))
    for index, tid in enumerate(path):
        result[index] = tid
    return result


def set_struct_offset(insn, operand: int, path: list[int], delta: int) -> bool:
    if not path:
        return False
    if not _legacy_structs():
        if any(ida_typeinf.get_tid_ordinal(tid) == 0 for tid in path):
            return False
        return ida_bytes.op_stroff(insn, operand, path, delta)

    import ida_nalt
    import ida_struct

    # Before IDA 9 these are IDB structure/member IDs, not TIL ordinals.
    if len(path) > ida_nalt.MAXSTRUCPATH or ida_struct.get_struc(path[0]) is None:
        return False
    if any(ida_struct.get_member_by_id(tid) is None for tid in path[1:]):
        return False
    native_path = _tid_array(path)
    return ida_bytes.op_stroff(insn, operand, native_path.cast(), len(path), delta)


def get_struct_offset_path(ea: int, operand: int):
    if not _legacy_structs():
        return ida_bytes.get_stroff_path(ea, operand)

    import ida_nalt
    import ida_pro

    path = ida_pro.tid_array(ida_nalt.MAXSTRUCPATH)
    delta = ida_pro.sval_pointer()
    count = ida_bytes.get_stroff_path(path.cast(), delta.cast(), ea, operand)
    if count <= 0:
        return None, None
    if count > ida_nalt.MAXSTRUCPATH:
        raise RuntimeError('IDA returned a structure path longer than MAXSTRUCPATH')
    return [path[index] for index in range(count)], delta.value()


def get_struct_path_name(tid: int):
    if not _legacy_structs():
        return ida_typeinf.get_tid_name(tid)

    import ida_struct

    return ida_struct.get_struc_name(tid) or ida_struct.get_member_fullname(tid)


def append_struct_fields(disp: int, operand: int, path: list[int], delta: int):
    if not _legacy_structs():
        return ida_name.append_struct_fields(disp, operand, path, 0, delta, True)
    native_path = _tid_array(path)
    return ida_name.append_struct_fields(disp, operand, native_path.cast(), 0, delta, True)
