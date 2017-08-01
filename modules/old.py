import string
from enum import Enum

from node import Node, Kind

MANGLING_MODULE_OBJC = '__ObjC'
MANGLING_MODULE_C = '__C'
STDLIB_NAME = 'Swift'

IsVariadic = Enum('IsVariadic', 'YES NO')

class FunctionSigSpecializationParamKind():
    CONSTANT_PROP_FUNCTION = 0
    CONSTANT_PROP_GLOBAL = 1
    CONSTANT_PROP_INTEGER = 2
    CONSTANT_PROP_FLOAT = 3
    CONSTANT_PROP_STRING = 4
    CLOSURE_PROP = 5
    BOX_TO_VALUE = 6
    BOX_TO_STACK = 7
    DEAD = 1 << 6
    OWNED_TO_GUARANTEED = 1 << 7
    SROA = 1 << 8

class NameSource():
    def __init__(self, text):
        self.text = text

    def hasAtLeast(self, n):
        return n <= len(self.text)

    def isEmpty(self):
        return len(self.text) == 0

    def __bool__(self):
        return not self.isEmpty()

    def peek(self):
        return self.text[0]

    def next(self):
        c = self.peek()
        self.advanceOffset(1)
        return c

    def nextIf(self, s):
        if len(self.text) < len(s) or self.text[:len(s)] != s:
            return False
        self.advanceOffset(len(s))
        return True

    def slice(self, n):
        return self.text[:n]

    def advanceOffset(self, len):
        self.text = self.text[len:]

    def getString(self):
        result = self.text
        self.advanceOffset(len(result))
        return result

class OldDemangler():
    def __init__(self, mangled_name):
        self.substitutions = []
        self.mangled = NameSource(mangled_name)

    def demangleTopLevel(self):
        print('demangleTopLevel({})'.format(self.mangled.text))
        if not self.mangled.nextIf('_T'):
            return None

        top_level = Node(Kind.GLOBAL)

        # Specialization prefixes
        if self.mangled.nextIf('TS'):
            node = self.demangleSpecializedAttribute()
            if not node:
                return None
            top_level.addChild(node)
            self.substitutions = []

            while self.mangled.nextIf('_TTS'):
                node = self.demangleSpecializedAttribute()
                if not node:
                    return None
                top_level.addChild(node)
                self.substitutions = []

            if not self.mangled.nextIf('_T'):
                return None
        elif self.mangled.nextIf('To'):
            top_level.addChild(Node(Kind.OBJC_ATTRIBUTE))
        elif self.mangled.nextIf('TO'):
            top_level.addChild(Node(Kind.NON_OBJC_ATTRIBUTE))
        elif self.mangled.nextIf('TD'):
            top_level.addChild(Node(Kind.DYNAMIC_ATTRIBUTE))
        elif self.mangled.nextIf('Td'):
            top_level.addChild(Node(Kind.DIRECT_METHOD_REFERENCE_ATTRIBUTE))
        elif self.mangled.nextIf('TV'):
            top_level.addChild(Node(Kind.VTABLE_ATTRIBUTE))

        node = self.demangleGlobal()
        if not node:
            return None
        top_level.addChild(node)

        if not self.mangled.isEmpty():
            top_level.addChild(Node(Kind.SUFFIX, text=self.mangled.getString()))

        return top_level

    def demangleNatural(self, num):
        print('demangleNatural({})'.format(self.mangled.text))
        if not self.mangled:
            return False, num

        if not self.mangled.peek() in string.digits:
            return False, num
        s = ""
        while True:
            if not self.mangled:
                return True, int(s)
            c = self.mangled.peek()
            if not c in string.digits:
                return True, int(s)
            else:
                s += self.mangled.next()

    def demangleGlobal(self):
        print('demangleGlobal({})'.format(self.mangled.text))
        if not self.mangled:
            return None

        # Type metadata
        if self.mangled.nextIf('M'):
            if self.mangled.nextIf('P'):
                pattern = Node(Kind.GENERIC_TYPE_METADATA_PATTERN)
                node = self.demangleType()
                if not node:
                    return None
                pattern.addChild(node)
                return pattern
            if self.mangled.nextIf('a'):
                accessor = Node(Kind.TYPE_METADATA_ACCESS_FUNCTION)
                node = self.demangleType()
                if not node:
                    return None
                accessor.addChild(node)
                return accessor
            if self.mangled.nextIf('L'):
                cache = Node(Kind.TYPE_METADATA_LAZY_CACHE)
                node = self.demangleType()
                if not node:
                    return None
                cache.addChild(node)
                return cache
            if self.mangled.nextIf('m'):
                metaclass = Node(Kind.METACLASS)
                node = self.demangleType()
                if not node:
                    return None
                metaclass.addChild(node)
                return metaclass
            if self.mangled.nextIf('n'):
                nominal_type = Node(Kind.NOMINAL_TYPE_DESCRIPTOR)
                node = self.demangleType()
                if not node:
                    return None
                nominal_type.addChild(node)
                return nominal_type
            if self.mangled.nextIf('f'):
                metadata = Node(Kind.FULL_TYPE_METADATA)
                node = self.demangleType()
                if not node:
                    return None
                metadata.addChild(node)
                return metadata
            if self.mangled.nextIf('p'):
                metadata = Node(Kind.PROTOCOL_DESCRIPTOR)
                node = self.demangleType()
                if not node:
                    return None
                metadata.addChild(node)
                return metadata
            metadata = Node(Kind.TYPE_METADATA)
            node = self.demangleType()
            if not node:
                return None
            metadata.addChild(node)
            return metadata

        # Partial application thunks
        if self.mangled.nextIf('PA'):
            print('TODO: implement partial application thunks')
            return None

        # Top-level types
        if self.mangled.nextIf('t'):
            print('TODO: implement top level types for consumers')
            return None

        # Value witnesses
        if self.mangled.nextIf('w'):
            print('TODO: implement value witnesses')
            return None

        # Offsets, value witness tables, and protocol witnesses
        if self.mangled.nextIf('W'):
            print('TODO: implement offsets value witness tables and protocol witnesses')
            return None

        # Other thunks
        if self.mangled.nextIf('T'):
            print('TODO: implement other thunks')
            return None

        return self.demangleEntity()

    def demangleGenericSpecialization(self, specialization):
        while not self.mangled.nextIf('_'):
            param = Node(Kind.GENERIC_SPECIALIZATION_PARAM)
            node = self.demangleType()
            if not node:
                return None
            param.addChild(node)

            while not self.mangled.nextIf('_'):
                node = self.demangleProtocolConformance()
                if not node:
                    return None
                param.addChild(node)
            specialization.addChild(param)

        return specialization

    def demangleFunctionSignatureSpecialization(self, specialization):
        param_count = 0
        while not self.mangled.nextIf('_'):
            param = Node(Kind.FUNCTION_SIGNATURE_SPECIALIZATION_PARAM, index=param_count)
            if self.mangled.nextIf('n_'):
                pass
            elif self.mangled.nextIf('cp'):
                if not self.demangleFuncSigSpecializationConstantProp(param):
                    return None
            elif self.mangled.nextIf('cl'):
                if not self.demangleFuncSigSpecializationClosureProp(param):
                    return None
            elif self.mangled.nextIf('i_'):
                result =  Node(Kind.FUNCTION_SIGNATURE_SPECIALIZATION_PARAM_KIND, index=FunctionSigSpecializationParamKind.BOX_TO_VALUE)
                if not result:
                    return None
                param.addChild(result)
            elif self.mangled.nextIf('k_'):
                result =  Node(Kind.FUNCTION_SIGNATURE_SPECIALIZATION_PARAM_KIND, index=FunctionSigSpecializationParamKind.BOX_TO_STACK)
                if not result:
                    return None
                param.addChild(result)
            else:
                value = 0
                if self.mangled.nextIf('d'):
                    value = value | FunctionSigSpecializationParamKind.DEAD
                if self.mangled.nextIf('g'):
                    value = value | FunctionSigSpecializationParamKind.OWNED_TO_GUARANTEED
                if self.mangled.nextIf('s'):
                    value = value | FunctionSigSpecializationParamKind.SROA
                if not self.mangled.nextIf('_'):
                    return None
                if not value:
                    return None

                result = Node(Kind.FUNCTION_SIGNATURE_SPECIALIZATION_PARAM_KIND, index=value)
                if not result:
                    return None
                param.addChild(result)

            specialization.addChild(param)
            param_count += 1

        return specialization

    def demangleProtocolConformance(self):
        t = self.demangleType()
        if not t:
            return None
        protocol = self.demangleProtocolName()
        if not protocol:
            return None
        context = self.demangleContext()
        if not context:
            return None
        proto_conformance = Node(Kind.PROTOCOL_CONFORMANCE)
        proto_conformance.addChild(t)
        proto_conformance.addChild(protocol)
        proto_conformance.addChild(context)
        return proto_conformance

    def demangleEntity(self):
        print('demangleEntity({})'.format(self.mangled.text))
        is_static = self.mangled.nextIf('Z')

        if self.mangled.nextIf('F'):
            entity_basic_kind = Node(Kind.FUNCTION)
        elif self.mangled.nextIf('v'):
            entity_basic_kind = Node(Kind.VARIABLE)
        elif self.mangled.nextIf('I'):
            entity_basic_kind = Node(Kind.INITIALIZER)
        elif self.mangled.nextIf('i'):
            entity_basic_kind = Node(Kind.SUBSCRIPT)
        else:
            return self.demangleNominalType()

        context = self.demangleContext()
        if not context:
            return None

        has_type = True
        name = ""
        if self.mangled.nextIf('D'):
            entity_kind = Node(Kind.DEALLOCATOR)
            has_type = False
        elif self.mangled.nextIf('d'):
            entity_kind = Node(Kind.DESCTRUCTOR)
            has_type = False
        elif self.mangled.nextIf('e'):
            entity_kind = Node(Kind.IVAR_INITIALIZER)
            has_type = False
        elif self.mangled.nextIf('E'):
            entity_kind = Node(Kind.IVAR_DESTROYER)
            has_type = False
        elif self.mangled.nextIf('C'):
            entity_kind = Node(Kind.ALLOCATOR)
        elif self.mangled.nextIf('c'):
            entity_kind = Node(Kind.CONSTRUCTOR)
        elif self.mangled.nextIf('a'):
            if self.mangled.nextIf('O'):
                entity_kind = Node(Kind.OWNING_MUTABLE_ADDRESSSOR)
            elif self.mangled.nextIf('o'):
                entity_kind = Node(Kind.NATIVE_OWNING_MUTABLE_ADDRESSOR)
            elif self.mangled.nextIf('p'):
                entity_kind = Node(Kind.NATIVE_PINNING_MUTABLE_ADDRESSOR)
            elif self.mangled.nextIf('u'):
                entity_kind = Node(Kind.UNSAFE_MUTABLE_ADDRESSOR)
            else:
                print('demangleEntity() couldn\'t handle addressor with suffix={}'.format(self.mangled.text))
                return None
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('g'):
            entity_kind = Node(Kind.GETTER)
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('G'):
            entity_kind = Node(Kind.GLOBAL_GETTER)
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('s'):
            entity_kind = Node(Kind.SETTER)
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('m'):
            entity_kind = Node(Kind.MATERIALIZE_FOR_SET)
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('w'):
            entity_kind = Node(Kind.WILL_SET)
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('W'):
            entity_kind = Node(Kind.DID_SET)
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('U'):
            entity_kind = Node(Kind.EXPLICIT_CLOSURE)
            name = self.demangleDeclName()
            if not name:
                return None
        elif self.mangled.nextIf('u'):
            entity_kind = Node(Kind.IMPLICIT_CLOSURE)
            name = self.demangleDeclName()
            if not name:
                return None
        elif entity_basic_kind == Kind.INITIALIZER:
            if self.mangled.nextIf('A'):
                entity_kind = Node(Kind.DEFAULT_ARGUMENT_INITIALIZER)
                name = self.demangleIndexAsNode()
                if not name:
                    return None
            elif self.mangled.nextIf('i'):
                entity_kind = Node(Kind.INITIALIZER)
            else:
                print('demangleEntity() couldn\'t handle initializer with suffix={}'.format(self.mangled.text))
                return None
            has_type = False
        else:
            entity_kind = entity_basic_kind
            name = self.demangleDeclName()
            if not name:
                return None

        entity = Node(entity_kind)
        entity.addChild(context)
        if name:
            entity.addChild(name)
        if has_type:
            t = self.demangleType()
            if not t:
                return None
            entity.addChild(t)
        if is_static:
            static_node = Node(Kind.STATIC)
            static_node.addChild(entity)
            return static_node

        return entity

    def demangleNominalType(self):
        print('demangleNominalType({})'.format(self.mangled.text))
        if self.mangled.nextIf('S'):
            return self.demangleSubstitutionIndex()
        if self.mangled.nextIf('V'):
            return self.demangleDeclarationName(Node(Kind.STRUCTURE))
        if self.mangled.nextIf('O'):
            return self.demangleDeclarationName(Node(Kind.ENUM))
        if self.mangled.nextIf('C'):
            return self.demangleDeclarationName(Node(Kind.CLASS))
        if self.mangled.nextIf('P'):
            return self.demangleDeclarationName(Node(Kind.PROTOCOL))
        return None

    def demangleBoundGenericArgs(self, nominal_type):
        if nominal_type.getNumChildren() == 0:
            return None

        parent_or_module = nominal_type.getChild(0)

        if (parent_or_module.kind != Kind.MODULE and
            parent_or_module.kind != Kind.FUNCTION and
            parent_or_module.kind != Kind.EXTENSION):
            result = Node(nominal_type.kind)
            result.addChild(parent_or_module)
            result.addChild(nominal_type.getChild(1))
            nominal_type = result

        args = Node(Kind.TYPE_LIST)
        while not self.mangled.nextIf('_'):
            t = self.demangleType()
            if not t:
                return None
            args.addChild(t)
            if self.mangled.isEmpty():
                return None

        if args.getNumChildren() == 0:
            return nominal_type

        unbound_type = Node(Kind.TYPE)
        unbound_type.addChild(nominal_type)

        if nominal_type.kind == Kind.CLASS:
            kind = Kind.BOUND_GENERIC_CLASS
        elif nominal_type.kind == Kind.STRUCTURE:
            kind = Kind.BOUND_GENERIC_STRUCTURE
        elif nominal_type.kind == Kind.ENUM:
            kind = Kind.BOUND_GENERIC_ENUM
        else:
            return None

        result = Node(kind)
        result.addChild(unbound_type)
        result.addChild(args)
        return result

    def demangleSpecializedAttribute(self):
        is_not_re_abstracted = False
        if self.mangled.nextIf('g') or (self.mangled.peek() == 'r'):
            is_not_re_abstracted = self.mangled.nextIf('r')
            kind = Kind.GENERIC_SPECIALIZATION_NOT_RE_ABSTRACTED if is_not_re_abstracted else Kind.GENERIC_SPECIALIZATION
            spec = Node(kind)

            if self.mangled.nextIf('q'):
                spec.addChild(Node(Kind.SPECIALIZATION_IS_FRAGILE))

            spec.addChild(Node(Kind.SPECIALIZATION_PASS_ID, index=int(self.mangled.next)))

            return self.demangleGenericSpecialization(spec)

        if self.mangled.nextIf('f'):
            spec = Node(Kind.FUNCTION_SIGNATURE_SPECIALIZATION)

            if self.mangled.nextIf('q'):
                spec.addChild(Node(Kind.SPECIALIZATION_IS_FRAGILE))

            spec.addChild(Node(Kind.SPECIALIZATION_PASS_ID, index=int(self.mangled.next())))

            return self.demangleFunctionSignatureSpecialization(spec)

        return None

    def demangleDeclName(self):
        print('demangleDeclName({})'.format(self.mangled.text))
        if self.mangled.nextIf('L'):
            discriminator = self.demangleIndexAsNode()
            if not discriminator:
                return None
            name = self.demangleIdentifier()
            if not name:
                return None

            local_name = Node(Kind.LOCAL_DECL_NAME)
            local_name.addChild(disciminator)
            local_name.addChild(name)
            return local_name
        elif self.mangled.nextIf('P'):
            discriminator = self.demangleIdentifier()
            if not discriminator:
                return None

            name = self.demangleIdentifier()
            if not name:
                return None

            private_name = Node(Kind.PRIVATE_DECL_NAME)
            private_name.addChild(discriminator)
            private_name.addChild(name)
            return private_name

        return self.demangleIdentifier()

    def demangleIdentifier(self, kind=None):
        print('demangleIdentifier({})'.format(self.mangled.text))
        if not self.mangled:
            return None

        is_puny_coded = self.mangled.nextIf('X')
        # TODO: WTF?

        is_operator = False
        if self.mangled.nextIf('o'):
            is_operator = True
            # TODO: not sure about this
            if kind:
                return None

            op_mode = self.mangled.next()
            if op_mode == 'p':
                kind = Node(Kind.PREFIX_OPERATOR)
            elif op_mode == 'P':
                kind = Node(Kind.POSTFIX_OPERATOR)
            elif op_mode == 'i':
                kind = Node(Kind.INFIX_OPERATOR)
            else:
                return None

        if not kind:
            kind = Kind.IDENTIFIER

        length = 0
        success, length = self.demangleNatural(length)
        if not success:
            return None
        if not self.mangled.hasAtLeast(length):
            return None

        identifier = self.mangled.slice(length)
        self.mangled.advanceOffset(length)

        #identifier = decode(identifier)
        if len(identifier) == 0:
            return None

        if is_operator:
            print('TODO: decode operator names for {}'.format(identifier))
            return None

        return Node(kind, identifier)

    def demangleIndex(self):
        print('demangleIndex({})'.format(self.mangled.text))
        natural = 0
        if self.mangled.nextIf('_'):
            natural = 0
            return True, natural
        success, natural = self.demangleNatural(natural)
        print('success={} natural={}'.format(success, natural))
        if success:
            if not self.mangled.nextIf('_'):
                return False, natural
            natural += 1
            return True, natural
        return False, natural

    def demangleIndexAsNode(self, kind=Node(Kind.NUMBER)):
        success, index = self.demangleIndex()
        if not success:
            return None
        return Node(kind, index=index)

    def createSwiftType(self, type_kind, name):
        print('createSwiftType({})'.format(name))
        t = Node(type_kind)
        t.addChild(Node(Kind.MODULE, text=STDLIB_NAME))
        t.addChild(Node(Kind.IDENTIFIER, text=name))
        return t

    def demangleSubstitutionIndex(self):
        print('demangleSubstitutionIndex({})'.format(self.mangled.text))
        if not self.mangled:
            return None
        if self.mangled.nextIf('o'):
            return Node(Kind.MODULE, text=MANGLING_MODULE_OBJC)
        if self.mangled.nextIf('C'):
            return Node(Kind.MODULE, text=MANGLING_MODULE_C)
        if self.mangled.nextIf('a'):
            return self.createSwiftType(Kind.STRUCTURE, 'Array')
        if self.mangled.nextIf('b'):
            return self.createSwiftType(Kind.STRUCTURE, 'Bool')
        if self.mangled.nextIf('c'):
            return self.createSwiftType(Kind.STRUCTURE, 'UnicodeScalar')
        if self.mangled.nextIf('d'):
            return self.createSwiftType(Kind.STRUCTURE, 'Double')
        if self.mangled.nextIf('f'):
            return self.createSwiftType(Kind.STRUCTURE, 'Float')
        if self.mangled.nextIf('i'):
            return self.createSwiftType(Kind.STRUCTURE, 'Int')
        if self.mangled.nextIf('V'):
            return self.createSwiftType(Kind.STRUCTURE, 'UnsafeRawPointer')
        if self.mangled.nextIf('v'):
            return self.createSwiftType(Kind.STRUCTURE, 'UnsafeMutableRawPointer')
        if self.mangled.nextIf('P'):
            return self.createSwiftType(Kind.STRUCTURE, 'UnsafePointer')
        if self.mangled.nextIf('p'):
            return self.createSwiftType(Kind.STRUCTURE, 'UnsafeMutablePointer')
        if self.mangled.nextIf('q'):
            return self.createSwiftType(Kind.ENUM, 'Optional')
        if self.mangled.nextIf('Q'):
            return self.createSwiftType(Kind.ENUM, 'ImplicitlyUnwrappedOptional')
        if self.mangled.nextIf('R'):
            return self.createSwiftType(Kind.STRUCTURE, 'UnsafeBufferPointer')
        if self.mangled.nextIf('r'):
            return self.createSwiftType(Kind.STRUCTURE, 'UnsafeMutableBufferPointer')
        if self.mangled.nextIf('S'):
            #ret = self.createSwiftType(Kind.STRUCTURE, 'String')
            #print('createSwiftType(String)')
            #if not ret:
            #    print('createSwiftType returned None')
            #return ret
            return self.createSwiftType(Kind.STRUCTURE, 'String')
        if self.mangled.nextIf('u'):
            return self.createSwiftType(Kind.STRUCTURE, 'UInt')

        print('demangleSubstitutionIndex made it past createSwiftType()')
        print('substitutions={}'.format(self.substitutions))
        success, index_sub = self.demangleIndex()
        print('success={} index_sub={}'.format(success, index_sub))
        if not success:
            return None
        if index_sub >= len(self.substitutions):
            return None
        return self.substitutions[index_sub]

    def demangleDeclarationName(self, kind):
        context = self.demangleContext()
        if not context:
            return None

        name = self.demangleDeclName()
        if not name:
            return None

        decl = Node(kind)
        decl.addChild(context)
        decl.addChild(name)
        self.substitutions.append(decl)
        return decl

    def demangleProtocolName(self):
        proto = self.demangleProtocolNameImpl()
        if not proto:
            return None

        t = Node(Kind.TYPE)
        t.addChild(proto)
        return t

    def demangleProtocolNameGivenContext(self, context):
        name = self.demangleDeclName()
        if not name:
            return None

        proto = Node(Kind.PROTOCOL)
        proto.addChild(context)
        proto.addChild(name)
        self.substitutions.append(proto)
        return proto

    def demangleProtocolNameImpl(self):
        if self.mangled.nextIf('S'):
            sub = self.demangleSubstitutionIndex()
            if not sub:
                return None
            if sub.kind == Kind.PROTOCOL:
                return sub
            if sub.kind != Kind.MODULE:
                return None
            return self.demangleProtocolNameGivenContext(sub)

        if self.mangled.nextIf('s'):
            stdlib = Node(Kind.MODULE, text=STDLIB_NAME)
            return self.demangleProtocolNameGivenContext(stdlib)

        return self.demangleDeclaratioinName(Kind.PROTOCOL)

    def demangleModule(self):
        print('demangleModule({})'.format(self.mangled.text))
        if self.mangled.nextIf('s'):
            return Node(Kind.MODULE, text=STDLIB_NAME)
        if self.mangled.nextIf('S'):
            module = self.demangleSubstitutionIndex()
            if not module:
                return None
            if module.kind != Kind.MODULE:
                return None
            return module

        module = self.demangleIdentifier(Kind.MODULE)
        if not module:
            return None
        self.substitutions.append(module)
        return module

    def demangleBoundGenericType(self):
        nominal_type = self.demangleNominalType()
        if not nominal_type:
            return None
        return self.demangleBoundGenericArgs(nominal_type)

    def demangleContext(self):
        print('demangleContext({})'.format(self.mangled.text))
        if not self.mangled:
            return None
        if self.mangled.nextIf('E'):
            ext = Node(Kind.EXTENSIONS)
            def_module = self.demangleModule()
            if not def_module:
                return None
            t = self.demangleContext()
            if not t:
                return None
            ext.addChild(def_module)
            ext.addChild(t)
            return ext

        if self.mangled.nextIf('e'):
            ext = Node(Kind.EXTENSIONS)
            def_module = self.demangleModule()
            if not def_module:
                return None
            print('TODO: implement demangleGenericSignature()')
            return None
            #sig = self.demangleGenericSignature()
            if not sig:
                return None
            t = self.demangleContext()
            if not t:
                return None
            ext.addChild(def_module)
            ext.addChild(t)
            ext.addChild(sig)
            return ext

        if self.mangled.nextIf('S'):
            return self.demangleSubstitutionIndex()
        if self.mangled.nextIf('s'):
            return Node(Kind.MODULE, text=STDLIB_NAME)
        if self.mangled.nextIf('G'):
            print('TODO: implement demangleBoundGenericType()')
            return None
            #return self.demangleBoundGenericType()
        if isStartOfEntity(self.mangled.peek()):
            return self.demangleEntity()
        return self.demangleModule()

    def demangleProtocolList(self):
        proto_list = Node(Kind.PROTOCOL_LIST)
        type_list = Node(Kind.TYPE_LIST)
        proto_list.addChild(type_list)
        while not self.mangled.nextIf('_'):
            proto = self.demangleProtocolName()
            if not proto:
                return None
            type_list.addChild(proto)
        return proto_list

    def demangleTuple(self, is_v):
        tuple =  Node(Kind.TUPLE)
        elt = None
        while not self.mangled.nextIf('_'):
            if not self.mangled:
                return None
            elt = Node(Kind.TUPLE_ELEMENT)

            if isStartOfIdentifier(self.mangled.peek()):
                label = self.demangleIdentifier(Kind.TUPLE_ELEMENT_NAME)
                if not label:
                    return None
                elt.addChild(label)

            t = self.demangleType()
            if not t:
                return None
            elt.addChild(t)
            tuple.addChild(elt)

        if is_v == IsVariadic.YES and elt:
            elt.reverseChildren()
            marker = Node(Kind.VARIADIC_MARKER)
            elt.addChild(marker)
            elt.reverseChildren()
        return tuple

    def postProcessReturnTypeNode(self, out_args):
        out_node = Node(Kind.RETURN_TYPE)
        out_node.addChild(out_args)
        return out_node

    def demangleType(self):
        print('demangleType({})'.format(self.mangled.text))
        t = self.demangleTypeImpl()
        if not t:
            #print('demangleTypeImpl() returned None with suffix={}'.format(self.mangled.text))
            return None
        node_type = Node(Kind.TYPE)
        node_type.addChild(t)
        return node_type

    def demangleFunctionType(self, kind):
        print('demangleFunctionType({})'.format(self.mangled.text))
        throws = False
        if self.mangled and self.mangled.nextIf('z'):
            throws = True
        in_args = self.demangleType()
        print('in_args={}'.format(in_args))
        if not in_args:
            return None
        out_args = self.demangleType()
        print('out_args={}'.format(out_args))
        if not out_args:
            return None
        block = Node(kind)

        if throws:
            block.addChild(Node(Kind.THROWS_ANNOTATION))

        in_node = Node(Kind.ARGUMENT_TUPLE)
        block.addChild(in_node)
        in_node.addChild(in_args)
        block.addChild(self.postProcessReturnTypeNode(out_args))
        return block

    def demangleTypeImpl(self):
        print('demangleTypeImpl({})'.format(self.mangled.text))
        if not self.mangled:
            return None

        c = self.mangled.next()
        if c == 'B':
            if not self.mangled:
                return None
            c = self.mangled.next()
            if c == 'b':
                return Node(Kind.BUILTIN_TYPE_NAME, text="Builtin.BridgeObject")

            if c == 'B':
                return Node(Kind.BUILTIN_TYPE_NAME, text="Builtin.UnsafeValueBuffer")

            if c == 'f':
                print('TODO: implement demangleBuiltinSize(size)')
                return None

            if c == 'i':
                print('TODO: implement demangleBuiltinSize(size)')
                return None

            if c == 'v':
                elts = 0
                success, elts = self.demangleNatural(elts)
                if sucess:
                    if not self.mangled.nextIf('B'):
                        return None
                    if self.mangled.nextIf('i'):
                        print('TODO: implement demangleBuiltinSize(size)')
                        return None
                    if self.mangled.nextIf('f'):
                        print('TODO: implement demangleBuiltinSize(size)')
                        return None
                    if self.mangled.nextIf('p'):
                        print('TODO: implement DemanglerPrinter()')
                        return None
            if c == 'O':
                return Node(Kind.BUILTIN_TYPE_NAME, text='Builtin.UnknownObject')
            if c == 'o':
                return Node(Kind.BUILTIN_TYPE_NAME, text='Builtin.NativeObject')
            if c == 'p':
                return Node(Kind.BUILTIN_TYPE_NAME, text='Builtin.RawPointer')
            if c == 'w':
                return Node(Kind.BUILTIN_TYPE_NAME, text='Builtin.Word')
            return None

        if c == 'a':
            return self.demangleDeclarationname(Kind.TYPE_ALIAS)
        if c == 'b':
            return self.demangleDeclarationname(Kind.ObjCBlock)
        if c == 'c':
            return self.demangleDeclarationname(Kind.CFunctionPointer)
        if c == 'D':
            t = self.demangleType()
            if not t:
                return None
            dynamic_self = Node(Kind.DYNAMIC_SELF)
            dynamic_self.addChild(t)
            return dynamic_self
        if c == 'E':
            if not self.mangled.nextIf('R'):
                return None
            if not self.mangled.nextIf('R'):
                return None
            # TODO: std::string() is unusual
            return Node(Kind.ERROR_TYPE, text="")
        if c == 'F':
            return self.demangleFunctionType(Kind.FUNCTION_TYPE)
        if c == 'f':
            return self.demangleFunctionType(Kind.UNCURRIED_FUNCTION_TYPE)
        if c == 'G':
            return self.demangleBoundGenericType()
        if c == 'X':
            print('TODO: implement X case')
            return None
        if c == 'K':
            return self.demangleFunctionType(Kind.AUTO_CLOSURE_TYPE)
        if c == 'M':
            t = self.demangleType()
            if not t:
                return None
            metatype = Node(Kind.METATYPE)
            metatype.addChild(t)
            return metatype
        if c == 'X':
            print('TODO: implement demangleMetatypeRepresentation')
            return None
        if c == 'P':
            if self.mangled.nextIf('M'):
                t = self.demangleType()
                if not t:
                    return None
                metatype = Node(Kind.EXISTENTIAL_METATYPE)
                metatype.addChild(t)
                return metatype
            return self.demangleProtocolList()
        if c == 'X':
            print('TODO: implement demangleMetatypeRepresentation')
            return None
        if c == 'Q':
            print('TODO: implement demangleArchetypeType')
            return None
            #return self.demangleArchetypeType()
        if c == 'q':
            print('TODO: implement demangleDependentType')
            return None
        if c == 'x':
            print('TODO: implement demangleDependentGenericParamType')
            return None
        if c == 'w':
            print('TODO: implement demangleAssociatedTypeSimple')
            return None
        if c == 'W':
            print('TODO: implement demangleAssociatedTypeCompound')
            return None
        if c == 'R':
            inout = Node(Kind.IN_OUT)
            t = self.demangleTypeImpl()
            if not t:
                return None
            inout.addChild(t)
            return inout
        if c == 'S':
            #ret = self.demangleSubstitutionIndex()
            #if not ret:
            #    print('demangleSubstitutionIndex() returned None with suffix={}'.format(self.mangled.text))
            #return ret
            return self.demangleSubstitutionIndex()
        if c == 'T':
            return self.demangleTuple(IsVariadic.NO)
        if c == 't':
            return self.demangleTuple(IsVariadic.YES)
        if c == 'u':
            print('TODO: implement demangleGenericSignature')
            return None
        if c == 'X':
            if self.mangled.nextIf('f'):
                return self.demangleFunctionType(Kind.THIN_FUNCTION_TYPE)
            if self.magled.nextIf('o'):
                t = self.demangleType()
                if not t:
                    return None
                unowned = Node(Kind.UNOWNED)
                unowned.addChild(t)
                return unowned
            if self.mangled.nextIf('u'):
                t = self.demangleType()
                if not t:
                    return None
                unowned = Node(Kind.UNMANAGED)
                unowned.addChild(t)
                return unowned
            if self.mangled.nextIf('w'):
                t = self.demangleType()
                if not t:
                    return None
                weak = Node(Kind.WEAK)
                weak.addChild(t)
                return weak
            if self.mangled.nextIf('F'):
                return self.demangleImplFunctionType()

            return None
        if isStartOfNominalType(c):
            return self.demangleDeclarationName(nominalTypeMarkerToNodeKind(c))
        return None

#    def demangleGenericSignature(self):
#    def demangleBoundGenericType(self):

def isStartOfIdentifier(c):
    if c in string.digits:
        return True
    return c == 'o'

def isStartOfNominalType(c):
    if c in 'CVO':
        return True
    return False

def isStartOfEntity(c):
    if c in 'FIvPsZ':
        return True
    return isStartOfNominalType(c)

def nominalTypeMarkerToNodeKind(c):
    if c == 'C':
        return Kind.CLASS
    if c == 'V':
        return Kind.STRUCTURE
    if c == 'O':
        return Kind.ENUM
    return Kind.IDENTIFIER

def demangleOldSymbolAsNode(s):
    demangler = OldDemangler(s)
    return demangler.demangleTopLevel()

