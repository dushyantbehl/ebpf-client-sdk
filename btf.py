##
# BPFTool generated BTF JSON parser.
# Can be extended to general BTF as well.
#
# Author: Dushyant Behl <dushyantbehl@in.ibm.com>

import logging
import copy
from struct import *

logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-4s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
log = logging.getLogger(__name__)

# Differnt kind of btf types
###
# BTF_KIND_INT            1       /* Integer      */
# BTF_KIND_PTR            2       /* Pointer      */
# BTF_KIND_ARRAY          3       /* Array        */
# BTF_KIND_STRUCT         4       /* Struct       */
# BTF_KIND_UNION          5       /* Union        */
# BTF_KIND_ENUM           6       /* Enumeration up to 32-bit values */
# BTF_KIND_FWD            7       /* Forward      */
# BTF_KIND_TYPEDEF        8       /* Typedef      */
# BTF_KIND_VOLATILE       9       /* Volatile     */
# BTF_KIND_CONST          10      /* Const        */
# BTF_KIND_RESTRICT       11      /* Restrict     */
# BTF_KIND_FUNC           12      /* Function     */
# BTF_KIND_FUNC_PROTO     13      /* Function Proto       */
# BTF_KIND_VAR            14      /* Variable     */
# BTF_KIND_DATASEC        15      /* Section      */
# BTF_KIND_FLOAT          16      /* Floating point       */
# BTF_KIND_DECL_TAG       17      /* Decl Tag     */
# BTF_KIND_TYPE_TAG       18      /* Type Tag     */
# BTF_KIND_ENUM64         19      /* Enumeration up to 64-bit values */
###

# btf is the top level type object.
def flattenBTF(btf):
    #print("btf is ")
    #print(json.dumps(btf))
    type = btf['kind']
    if type == "INT":
        return flattenBTFInt(btf)
    if type == "PTR":
        return flattenBTFPtr(btf)
    if type == "ARRAY":
        return flattenBTFArray(btf)
    if type == "STRUCT":
        return flattenBTFStructOrUnion(btf)
    if type == "UNION":
        return flattenBTFStructOrUnion(btf)
    if type == "TYPEDEF":
        return flattenBTFTypedef(btf)
    if type == "FLOAT":
        return flattenBTFFloat(btf)
    if type == "ENUM" or type == 'ENUM64':
        return flattenBTFEnum(btf)
    else:
        raise Exception("Unknown type "+type)

def flattenBTFNotImplemented(btf):
    log.error("Type "+btf['type']+" is not implemented")
    return {}

def flattenBTFBaseObject(btf):
    # Insert input here. Later maybe we move it somewhere else
    ret = {
        'type_name': btf['name'],
        'size': btf['size'],
        'kind': btf['kind'],
        'input': None
    }
    return ret

def flattenBTFInt(btf):
    return flattenBTFBaseObject(btf)

def flattenBTFEnum(btf):
    return flattenBTFBaseObject(btf)

def flattenBTFFloat(btf):
    return flattenBTFBaseObject(btf)

def flattenBTFPtr(btf):
    subType = btf['type']
    return flattenBTF(subType)

# Length of Array?
# https://docs.kernel.org/bpf/btf.html#btf-kind-array
# The above link suggests that arrays have a struct btf_array
# which contains number of elements. If this is populated then
# it can be extracted from the ELF by btf parsing eventually
# 
# And it seems like pahole and llvm both cannot support multi-dimensional
# array so that might be out of question for now
def flattenBTFArray(btf):
    subType = btf['type']
    variable_name = btf['name']
    member = flattenBTF(subType)
    del member['input']
    ret = {
            'variable_name': variable_name,
            'kind': btf['kind'],
            'input': [],
            'member': member
        }
    return ret

def flattenBTFStructOrUnion(btf):
    members = btf['members']
    variable_name = btf['name']
    member_collection = []
    for member in members:
        m = {}
        m['variable_name'] = member['name']
        m = m | flattenBTF(member['type'])
        member_collection.append(m)
    ret = {
            'variable_name': variable_name,
            'kind': btf['kind'],
            'member': member_collection
        }
    return ret

def flattenBTFFWD(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFTypedef(btf):
    subType = btf['type']
    return flattenBTF(subType)

def flattenBTFVolatile(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFConst(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFRestrict(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFFunc(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFFuncProto(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFVAR(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFDATASEC(btf):
    return flattenBTFNotImplemented(btf)

def flattenBTFDeclTag(btf):
    return flattenBTFNotImplemented(btf)

def getPackFormatForTypeName(name):
    if name == 'char':
        return 'b'
    elif name == 'unsigned char':
        return 'B'
    elif name == 'short':
        return 'h'
    elif name == 'unsigned short':
        return 'H'
    elif name == 'int':
        return 'i'
    elif name == 'unsigned int':
        return 'I'
    elif name == 'long':
        return 'l'
    elif name == 'unsigned long':
        return 'L'
    elif name == 'long long':
        return 'q'
    elif name == 'unsigned long long':
        return 'Q'
    elif name == 'float':
        return 'f'
    else:
        raise Exception('Unknown type name '+name)

def convertToType(val, type):
    try:
        _val = type(val)
        return _val
    except ValueError:
        return None

def convertBaseType(flatten_obj, type):
    try:
        input = flatten_obj['input']
        if input is None: # special case for unions
            return None
        variable_name = flatten_obj['variable_name']
        kind = flatten_obj['kind']
        size = flatten_obj['size']
        type_name = flatten_obj['type_name']
        data = convertToType(input, type)
        if data is None:
            raise Exception("Failed to convert the input variable "+
                            variable_name+" to type "+kind)
        fmt = '!'+getPackFormatForTypeName(type_name)
        raw = pack(fmt, data)
        log.info('Converted type '+kind+' input '+str(input)+' to '+raw.hex())
        #if len(raw) != size:
        #    raise Exception("Size of raw bytes "+
        #                    len(raw)+" is not equal to size "+size)
        return raw
    except Exception as e:
        raise Exception(str(e))

def convertArrayType(array_obj):
    try:
        variable_name = array_obj['variable_name']
        # array has one member
        member = array_obj['member']
        # array input array
        input_array = array_obj['input']

        members = []
        for input in input_array:
            m = copy.deepcopy(member)
            m['input'] = input
            members.append(m)

        raw_members = []
        for member in members:
            raw_val = generateRawValue(member)
            if raw_val is None:
                raise Exception('Member '+member['variable_name']+' doesnt contain input')
            raw_members.append(raw_val)
        raw_array = None
        for raw_member in raw_members:
            if raw_array == None:
                raw_array = raw_member
            else:
                raw_array += raw_member
        log.info('Converted STRUCT '+variable_name+' to '+raw_array.hex())
        return raw_array
    except Exception as e:
        raise Exception(str(e))

def convertStructType(struct_obj):
    try:
        variable_name = struct_obj['variable_name']
        members = struct_obj['member']
        raw_members = []
        for member in members:
            raw_val = generateRawValue(member)
            if raw_val is None:
                raise Exception('Member '+member['variable_name']+' doesnt contain input')
            raw_members.append(raw_val)
        raw_struct = None
        for raw_member in raw_members:
            if raw_struct == None:
                raw_struct = raw_member
            else:
                raw_struct += raw_member
        log.info('Converted STRUCT '+variable_name+' to '+raw_struct.hex())
        return raw_struct
    except Exception as e:
        raise Exception(str(e))

def convertUnionType(union_obj):
    try:
        variable_name = union_obj['variable_name']
        members = union_obj['member']
        raw_union = None
        for member in members:
            raw_val = generateRawValue(member)
            if raw_val is None:
                continue
            raw_union = raw_val
            break
        if raw_union is None:
            raise Exception('No member of union '+variable_name+' is set')
        log.info('Converted UNION '+variable_name+' to '+raw_union.hex())
        return raw_union
    except Exception as e:
        raise Exception(str(e))

# Code to generate raw hex from flatten btf object
def generateRawValue(flatten_obj):
    if flatten_obj is None:
        return None
    kind = flatten_obj['kind']
    if kind == 'INT' or kind == 'ENUM':
       return convertBaseType(flatten_obj=flatten_obj, type=int)
    elif kind == 'FLOAT':
       return convertBaseType(flatten_obj=flatten_obj, type=float)
    elif kind == 'STRUCT':
        return convertStructType(struct_obj=flatten_obj)
    elif kind == 'UNION':
        return convertUnionType(union_obj=flatten_obj)
    else:
        raise Exception('Unknown kind '+kind)