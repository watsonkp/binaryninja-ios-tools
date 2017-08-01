import logging, os

from binaryninja.plugin import PluginCommand
from binaryninja.log import log_error
from binaryninja.lowlevelil import LowLevelILOperation
from binaryninja.enums import SymbolType

from modules import classlist_parser
from modules import demangler

def define_classes(bv):
    if bv.view_type != 'Mach-O':
        log_error('BinaryView.view_type must be "Mach-O"')
        return

    supported_platforms = ['mac-armv7']
    if bv.platform.name not in supported_platforms:
        log_error("{} platform is not supported. Supported platforms are {}".format(bv.platform.name, supported_platforms))
        return

    if not bv.get_section_by_name("__objc_classlist"):
        log_error("Could not find an __objc_classlist section")
        return

    classlist_parser.define_types(bv)
    classlist_parser.define_objc_classlist(bv)

def demangleImportsInFunction(bv, f):
    LOG_FILE='/Users/Kevin/debug-log.txt'
    os.remove(LOG_FILE)
    logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG) 
    logging.debug('Calling demangleSymbolAsNode()...')
    skipped = []
    successful = []
    for block in f.low_level_il:
    #for block in bv.get_function_at(here).low_level_il:
        for instruction in block:
            if not instruction.prefix_operands[0].operation == LowLevelILOperation.LLIL_CALL:
                continue
            if not instruction.prefix_operands[1].operation == LowLevelILOperation.LLIL_CONST_PTR:
                print('WARNING: unfamiliar call operand in {}'.format(instruction))
                continue
            if not isinstance(instruction.prefix_operands[2], (int, long)):
                print('WARNING: unfamiliar call operand in {}'.format(instruction))
                continue
            symbol = bv.get_symbol_at(instruction.prefix_operands[2])
            if symbol and symbol.type == SymbolType.ImportedFunctionSymbol:
                #print(symbol.name)
                #demangler.demangleImport(bv, instruction.prefix_operands[2])
                #demangler.demangleImport(bv, symbol.name)
                name = symbol.name
                if name[:2] == '__':
                    name = name[1:]
                try:
                    result = demangler.demangleSymbolAsNode(bv, name)
                    if not result:
                        skipped.append(symbol.name)
                        print('Skipping {}'.format(symbol.name))
                        continue
                    successful.append(symbol.name)
                    print(result)
                    #print(demangler.getNodeTreeAsString(result))
                except Exception as e:
                    logging.exception(e)

    print(len(skipped))
    print(skipped)
    print(len(successful))
    print(successful)

PluginCommand.register("Define Objective-C classes", "Parses the objc_classlist section to define Objective C and Swift classes", define_classes)
PluginCommand.register_for_address("Demangle Swift symbol", "Demangles the Swift symbol name at the given address", demangler.demangleAddress)
PluginCommand.register_for_function("Demangle imported Swift symbols", "Demangles the imported Swift symbol names in the given function", demangleImportsInFunction)
