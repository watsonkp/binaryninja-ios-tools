import string
from enum import Enum
from binaryninja import types

from node import Node, Kind
from old import demangleOldSymbolAsNode

# Using the enum34 package on the recommendation of https://stackoverflow.com/a/1695250/689100
# In the Binary Ninja console
# from setuptools.command import easy_install
# easy_install.main(["-U", "enum34"])
# Needed to grant user write permissions on C:\Program Files\Vector35\BinaryNinja\plugins\Lib\site-packages


Type_Printing = Enum('Type_Printing', 'NO_TYPE')

def getManglingPrefixLength(mangled_name):
    if mangled_name[:3] == '_T0':
        return 3
    offset = 1 if mangled_name[0] == '_' else 0
    if mangled_name[offset:offset+2] == '$S':
        return offset + 2
    return 0

def isMangledName(mangled_name):
    return getManglingPrefixLength(mangled_name) != 0

def isSwiftSymbol(mangled_name):
    if mangled_name[:2] == '_T':
        return True
    return getManglingPrefixLength(mangled_name) != 0


def demangleSymbolAsNode(bv, s):
    # TODO: hook into the existing stuff and test
    if isMangledName(s):
        mangled = Mangled(s)
        mangled.demangleSymbol()
        return
    return demangleOldSymbolAsNode(s)

def getNodeTreeAsString(tree):
    printNode(tree)


# TODO: use this as Node.__str__, maybe?
def printNode(node, as_prefix_context=False):
    if node.kind == Kind.GLOBAL:
        return printChildren(node)
    elif node.kind == Kind.TYPE_MANGLING:
        return printNode(node.children[0])
    elif node.kind == Kind.TYPE:
        return printNode(node.children[0])
    elif node.kind == Kind.CLASS:
        return printEntity(node, as_prefix_context, Type_Printing.NO_TYPE, True)
    elif node.kind == Kind.MODULE:
        return node.text
    elif node.kind == Kind.IDENTIFIER:
        return node.text
    else:
        print("Unrecognized kind: {}".format(node.kind))
        return None

def printChildren(node):
    s = ""
    for child in node.children:
        s += printNode(child)
    return s

def printEntity(entity, as_prefix_context, type_printing, has_name, extra_name="", extra_index=-1):
    s = ""
    context = entity.children[0]
    s += printNode(context, True)
    s += "."
    if has_name:
        s += printNode(entity.children[1])
    return s

class NodeStack():
    def __init__(self):
        self.stack = []

    def popNode(self):
        if len(self.stack) == 0:
            return Node()
        node = self.stack.pop()
        return node

    def pushNode(self, node):
        self.stack.append(node)

class Mangled():
    def __init__(self, mangled_name):
        self.name = mangled_name
        self.position = 0
        self.tree = None
        self.stack = NodeStack()

    def demangleSymbol(self):
        if self.name[:3] ==  "_Tt":
            self.position = 3
# TODO: return the node, don't use a member
            print(self.demangleObjCTypeName())
            return
        print("Don't know how to demangle {}".format(self.name))

    def demangleObjCTypeName(self):
        t = Node(Kind.TYPE)
        self.tree = Node(Kind.GLOBAL).addChild(Node(Kind.TYPE_MANGLING).addChild(t))
        if self.name[self.position] == 'C':
            self.position += 1
            nominal = Node(Kind.CLASS)
            t.addChild(nominal)
        elif self.name[self.position] == 'P':
            self.position += 1
            print('Is a protocol')
        else:
            return None

        if self.name[self.position] == 's':
            nominal.addChild(Node(Kind.MODULE,  'Swift'))
        else:
            module = self.demangleIdentifier()
            if not module:
                return None
            module.kind = Kind.MODULE
            nominal.addChild(module)

        identifier = self.demangleIdentifier()
        if not identifier:
            return None
        nominal.addChild(identifier)

        return self.tree

    def demangleIdentifier(self):
        has_word_substrings = False
        is_punycoded = False
        if self.name[self.position] not in string.digits:
            return None
        if self.name[self.position] == '0':
            self.position += 1
            if self.name[self.position] == '0':
                self.position += 1
                is_punycoded = True
            else:
                has_word_substrings = True

        while has_word_substrings:
            print("ERROR: It has word substrings, which haven't been implemented")
            return None

        num_chars = self.demangleNatural()
        if num_chars <= 0:
            return None
        if is_punycoded:
            print("ERROR: {} is punycoded, which hasn't been implemented".format(self.name))
            return None
        if self.position + num_chars > len(self.name):
            return None
        if is_punycoded:
            print("ERROR: {} is punycoded, which hasn't been implemented".format(self.name))
            return None
        else:
            identifier = self.name[self.position:self.position + num_chars]
            self.position += num_chars

        if len(identifier) == 0:
            return None

        identifier_node = Node(Kind.IDENTIFIER, text=identifier)

        return identifier_node
        
    def demangleNatural(self):
        length = 0
        for c in self.name[self.position:]:
            if c not in string.digits:
                break
            length += 1
        num_chars = int(self.name[self.position:self.position + length])
        self.position += length
        return num_chars

def demangleAddress(bv, address):
    symbol = bv.get_symbol_at(address)
    if not symbol:
        print('No symbol found at 0x{:x}'.format(address))
        return
    demangled = demangleString(symbol.name)
    if not demangled:
        return
    # If multiple symbols for the same address are defined, only the most recent symbol will ever be used.
    # per https://api.binary.ninja/binaryninja.binaryview-module.html
    bv.define_user_symbol(types.Symbol(symbol.type, symbol.address, demangled))

def demangleString(s):
    if s[:2] == '__':
        s = s[1:]
    if not isSwiftSymbol(s):
        print('{} is not a Swift symbol'.format(s))
        return None
    mangled = Mangled(s)
    mangled.demangleSymbol()
    demangled = printNode(mangled.tree)
    if not demangled:
        print('Failed to demangle {}'.format(s))
        return None
    return demangled

def demangleImport(bv, s):
    if s[:2] == '__':
        s = s[1:]
    if not isSwiftSymbol(s):
        print('{} is not a Swift symbol'.format(s))
        return None
    mangled = Mangled(s)
    #mangled.demangleSymbol()
    mangled.demangleType()
