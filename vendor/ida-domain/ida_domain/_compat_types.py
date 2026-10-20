"""Type-library operations using APIs available in IDAPython 8.0."""

from __future__ import annotations

import ida_typeinf

# These SDK records were renamed after IDA 8.0. Keep aliases local; other
# plugins must continue to see the unmodified IDAPython modules.
udm_t = (
    ida_typeinf.udm_t if hasattr(ida_typeinf, 'udm_t')
    else ida_typeinf.udt_member_t
)
edm_t = (
    ida_typeinf.edm_t if hasattr(ida_typeinf, 'edm_t')
    else ida_typeinf.enum_member_t
)


def iter_named_types(library):
    name = ida_typeinf.first_named_type(library, ida_typeinf.NTF_TYPE)
    while name:
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(library, name):
            yield tif
        name = ida_typeinf.next_named_type(library, name, ida_typeinf.NTF_TYPE)


def iter_numbered_types(library):
    limit_fn = getattr(ida_typeinf, 'get_ordinal_limit', None)
    if limit_fn is None:
        limit_fn = ida_typeinf.get_ordinal_qty
    limit = limit_fn(library)
    # IDA 8 returns uint32(-1) for libraries without numbered types.
    if limit in (-1, 0xFFFFFFFF):
        return
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(library, ordinal):
            yield tif


def iter_enum_members(tif):
    details = ida_typeinf.enum_type_data_t()
    if tif.get_enum_details(details):
        yield from details


def enable_numbered_types(library):
    enable = getattr(ida_typeinf, 'enable_numbered_types', None)
    if enable is not None:
        enable(library, True)
    else:
        # IDAPython 8 does not wrap enable_numbered_types(). Local IDB types
        # already have ordinals. Never allocate a dummy ordinal or loop to -1.
        if ida_typeinf.get_ordinal_qty(library) in (-1, 0xFFFFFFFF):
            raise NotImplementedError(
                'Enabling numbered types in an external TIL requires a newer '
                'IDAPython; use the local database type library on IDA 8.0'
            )


def type_predicate(value, name):
    """Read type attributes available in this SDK.

    Newer attribute categories which IDA 8 cannot represent are omitted.
    Legacy enum representation and calling conventions have explicit adapters.
    """
    method = getattr(value, name, None)
    if method is not None:
        return method()
    if name == 'is_bf':
        return bool(value.bte & ida_typeinf.BTE_BITMASK)
    if name == 'is_number_signed':
        return value.is_sdec()
    if name == 'is_dec':
        return value.is_sdec() or value.is_udec()
    if name in ('is_user_cc', 'is_swift_cc'):
        predicate = getattr(ida_typeinf, name, None)
        return bool(predicate(value.cc)) if predicate is not None else False
    if name == 'is_punknown':
        return value.is_ptr() and value.get_pointed_object().is_unknown()
    if name == 'is_valid_bitfield':
        # The caller has already successfully extracted bitfield details.
        return True
    if name in {
        'is_fixed', 'is_oct', 'is_bin', 'is_shex', 'is_soct', 'is_sbin',
        'has_lzero', 'is_varmember',
    }:
        return False
    raise AttributeError(f'{type(value).__name__} has no predicate {name}')


def build_legacy_udt(members, is_union=False):
    """Use IDA's C parser to calculate the native layout on IDA 8.

    members contains (name, tinfo_t, byte_offset_or_None) tuples.
    Explicit offsets are applied to the resulting SDK member records in bits.
    """
    declarations = []
    for name, tif, _ in members:
        field = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, '')
        if not field:
            raise ValueError(f'Cannot print the type of member {name!r}')
        declarations.append(field.rstrip(';') + ';')
    kind = 'union' if is_union else 'struct'
    result = ida_typeinf.tinfo_t()
    declaration = kind + ' { ' + ' '.join(declarations) + ' };'
    if not ida_typeinf.parse_decl(result, None, declaration, ida_typeinf.PT_SIL):
        raise ValueError(f'Cannot parse {kind} declaration')
    if any(offset is not None for _, _, offset in members):
        details = ida_typeinf.udt_type_data_t()
        if not result.get_udt_details(details):
            raise ValueError('Cannot read parsed structure layout')
        for index, (_, _, offset) in enumerate(members):
            if offset is not None:
                if offset < 0:
                    raise ValueError('Member offsets must not be negative')
                details[index].offset = offset * 8
        if not result.create_udt(details, ida_typeinf.BTF_UNION if is_union else ida_typeinf.BTF_STRUCT):
            raise ValueError('Invalid explicit member layout')
        verified = ida_typeinf.udt_type_data_t()
        if not result.get_udt_details(verified) or any(
            offset is not None and verified[index].offset != offset * 8
            for index, (_, _, offset) in enumerate(members)
        ):
            raise NotImplementedError(
                'This SDK did not preserve the requested explicit member offsets; '
                'use a C declaration with explicit padding'
            )
    return result


def build_legacy_enum(members, base_size, is_bitmask):
    details = ida_typeinf.enum_type_data_t()
    if base_size not in (1, 2, 4, 8):
        raise ValueError('Enum size must be 1, 2, 4, or 8 bytes')
    # BTE_SIZE_MASK stores log2(size) + 1 (zero means compiler default).
    details.bte = (
        ida_typeinf.BTE_ALWAYS | ida_typeinf.BTE_HEX | base_size.bit_length()
    )
    if is_bitmask:
        raise NotImplementedError(
            'IDA 8 bitmask enums need explicit mask groups; use ida_enum or parse a declaration'
        )
    for name, value in members:
        member = edm_t()
        member.name = name
        member.value = value
        details.push_back(member)
    result = ida_typeinf.tinfo_t()
    if not result.create_enum(details):
        raise ValueError('Cannot create enum')
    return result
