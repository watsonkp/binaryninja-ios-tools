from binaryninja import *

from demangler import demangleString

def define_types(bv):
    t, name = bv.parse_type_string("struct {void *isa; void *superclass; void *cache; void *vtable; void *data;} objc_class")
    bv.define_user_type(name, t)

    t, name = bv.parse_type_string("struct { uint32_t flags; uint32_t instanceStart; uint32_t instanceSize; const uint8_t * ivarLayout; const char * name; void * baseMethodList; void * baseProtocols; void * ivars; const uint8_t * weakIvarLayout; void *baseProperties; } class_ro_t") 
    bv.define_user_type(name, t)

    t, name = bv.parse_type_string("struct {char *name; const char *types; void *imp;} method_t")
    bv.define_user_type(name, t)
    t, name = bv.parse_type_string("struct {uint32_t entsizeAndFlags; uint32_t count; method_t first;} method_list_t")
    bv.define_user_type(name, t)

def define_objc_class_ptr(bv, br, addr):
    objc_class_ptr, _ = bv.parse_type_string("objc_class *foo")
    bv.define_user_data_var(addr, objc_class_ptr)
    ptr = br.read32()
    offset = br.offset
    define_objc_class(bv, br, ptr)
    br.seek(offset)

def define_objc_class(bv, br, objc_class_ptr):
    objc_class = bv.get_type_by_name("objc_class")
    for member in objc_class.structure.members:
        if member.name == "data":
            data_offset = member.offset
            break

    bv.define_user_data_var(objc_class_ptr, objc_class)

    br.seek(objc_class_ptr + data_offset)
    objc_class_data = br.read32()
    if objc_class_data & 0x1:
        class_ro_t_ptr = objc_class_data & ~0x1
    else:
        class_ro_t_ptr = objc_class_data

    define_class_ro_t(bv, br, class_ro_t_ptr)

def define_class_ro_t(bv, br, class_ro_t_ptr):
    class_ro_t = bv.get_type_by_name("class_ro_t")
    bv.define_user_data_var(class_ro_t_ptr, class_ro_t)

    for member in class_ro_t.structure.members:
        if member.name == "baseMethodList":
            method_list_offset = member.offset
            continue
        if member.name == "name":
            name_offset = member.offset

    br.seek(class_ro_t_ptr + name_offset)
    name_ptr = br.read32()
    name = get_string_data_at(bv, br, name_ptr)
    demangled = demangleString(name)
    if demangled:
        name = demangled
    bv.define_user_symbol(types.Symbol(enums.SymbolType.DataSymbol, class_ro_t_ptr, name))

    br.seek(class_ro_t_ptr + method_list_offset)
    base_method_list = br.read32()
    if base_method_list == 0:
        return
    define_method_list_t(bv, br, name, base_method_list)

def define_method_list_t(bv, br, class_name, method_list_t_ptr):
    method_list_t = bv.get_type_by_name("method_list_t")
    bv.define_user_data_var(method_list_t_ptr, method_list_t)

    for member in method_list_t.structure.members:
        if member.name == "first":
            first_offset = member.offset
            continue
        if member.name == "count":
            count_offset = member.offset
            continue

    first = method_list_t_ptr + first_offset
    br.seek(method_list_t_ptr + count_offset)
    count = br.read32()
    method_t_size = bv.get_type_by_name("method_t").structure.width
    define_method_t(bv, br, class_name, first, first=True)
    for i in range(1, count):
        define_method_t(bv, br, class_name, first + i * method_t_size)

def define_method_t(bv, br, class_name, method_t_ptr, first=False):
    method_t = bv.get_type_by_name("method_t")
    if not first:
        bv.define_user_data_var(method_t_ptr, method_t)

    for member in method_t.structure.members:
        if member.name == "name":
            name_offset = member.offset
            continue
        if member.name == "imp":
            imp_offset = member.offset
            continue
    br.seek(method_t_ptr + name_offset)
    name_ptr = br.read32()
    name = get_string_data_at(bv, br, name_ptr)
    br.seek(method_t_ptr + imp_offset)
    imp_ptr = br.read32()
    bv.get_function_at(imp_ptr).name = class_name + "." + name

def define_objc_classlist(bv):
    br = BinaryReader(bv)
    objc_classlist = bv.get_section_by_name("__objc_classlist")
    br.seek(objc_classlist.start)
    for addr in range(objc_classlist.start, objc_classlist.start + objc_classlist.length, 4):
        define_objc_class_ptr(bv, br, addr)

def get_string_data_at(bv, br, addr):
    s = bv.get_strings(addr, 1)[0]
    br.seek(s.start)
    s_data = br.read(s.length)
    return s_data
