from enum import Enum

Kind = Enum('Kind', 'ALLOCATOR ARGUMENT_TUPLE BOUND_GENERIC_ENUM CLASS CONSTRUCTOR DEALLOCATOR DEFAULT_ARGUMENT_INITIALIZER DESCTRUCTOR DID_SET DIRECT_METHOD_REFERENCE_ATTRIBUTE DYNAMIC_ATTRIBUTE ENUM EXPLICIT_CLOSURE EXTENSIONS FULL_TYPE_METADATA FUNCTION FUNCTION_SIGNATURE_SPECIALIZATION FUNCTION_SIGNATURE_SPECIALIZATION_PARAM FUNCTION_SIGNATURE_SPECIALIZATION_PARAM_KIND FUNCTION_TYPE GENERIC_TYPE_METADATA_PATTERN GENERIC_SPECIALIZATION GENERIC_SPECIALIZATION_NOT_RE_ABSTRACTED GENERIC_SPECIALIZATION_PARAM GETTER GLOBAL GLOBAL_GETTER IDENTIFIER IMPLICIT_CLOSURE INITIALIZER IVAR_DESTROYER IVAR_INITIALIZER LOCAL_DECL_NAME MATERIALIZE_FOR_SET METACLASS MODULE NATIVE_OWNING_MUTABLE_ADDRESSOR NATIVE_PINNING_MUTABLE_ADDRESSOR NOMINAL_TYPE_DESCRIPTOR NON_OBJC_ATTRIBUTE NUMBER OBJC_ATTRIBUTE OWNING_MUTABLE_ADDRESSSOR PRIVATE_DECL_NAME PROTOCOL PROTOCOL_CONFORMANCE PROTOCOL_DESCRIPTOR PROTOCOL_LIST SETTER SPECIALIZATION_IS_FRAGILE SPECIALIZATION_PASS_ID STATIC STRUCTURE SUBSCRIPT RETURN_TYPE SUFFIX THROWS_ANNOTATION TUPLE TUPLE_ELEMENT TUPLE_ELEMENT_NAME TYPE TYPE_LIST TYPE_MANGLING TYPE_METADATA TYPE_METADATA_ACCESS_FUNCTION TYPE_METADATA_LAZY_CACHE UNCURRIED_FUNCTION_TYPE UNSAFE_MUTABLE_ADDRESSOR VARIABLE VARIADIC_MARKER VTABLE_ATTRIBUTE WILL_SET')

class Node():
    def __init__(self, kind, text="", index=-1):
        self.kind = kind
        self.children = []
        self.text = text
        if index >= 0:
            self.index = index

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        if self.text != "":
            if len(self.children) == 0:
                return "{{{}({})}}".format(self.kind, self.text, self.children)
            return "{{{}({}) children: {}}}".format(self.kind, self.text, self.children)
        return "{{{} children: {}}}".format(self.kind, self.children)

    def getNumChildren(self):
        return len(self.children)

    def getChild(self, n):
        return self.children[n]

    def addChild(self, child):
        self.children.append(child)
        return self

    def reverseChildren(self, starting_at=0):
        self.children = self.children[:starting_at] + self.children[starting_at:][::-1]
