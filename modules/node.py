from enum import Enum

Kind = Enum('Kind', 'ALLOCATOR ARGUMENT_TUPLE BOUND_GENERIC_ENUM CLASS CONSTRUCTOR DEALLOCATOR DEFAULT_ARGUMENT_INITIALIZER DESCTRUCTOR DID_SET DIRECT_METHOD_REFERENCE_ATTRIBUTE DYNAMIC_ATTRIBUTE ENUM EXPLICIT_CLOSURE EXTENSIONS FUNCTION FUNCTION_TYPE GETTER GLOBAL GLOBAL_GETTER IDENTIFIER IMPLICIT_CLOSURE INITIALIZER IVAR_DESTROYER IVAR_INITIALIZER LOCAL_DECL_NAME MATERIALIZE_FOR_SET MODULE NATIVE_OWNING_MUTABLE_ADDRESSOR NATIVE_PINNING_MUTABLE_ADDRESSOR NON_OBJC_ATTRIBUTE NUMBER OBJC_ATTRIBUTE OWNING_MUTABLE_ADDRESSSOR PRIVATE_DECL_NAME PROTOCOL PROTOCOL_LIST SETTER STATIC STRUCTURE SUBSCRIPT RETURN_TYPE SUFFIX THROWS_ANNOTATION TUPLE TUPLE_ELEMENT TUPLE_ELEMENT_NAME TYPE TYPE_LIST TYPE_MANGLING UNCURRIED_FUNCTION_TYPE UNSAFE_MUTABLE_ADDRESSOR VARIABLE VARIADIC_MARKER VTABLE_ATTRIBUTE WILL_SET')

class Node():
    def __init__(self, kind, text=""):
        self.kind = kind
        self.children = []
        self.text = text

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
