##
# BPFTool generated BTF JSON parser.
# Can be extended to general BTF as well.
#
# Author: Dushyant Behl <dushyantbehl@in.ibm.com>

import logging
import json
import copy

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

# Meta is the top level type object.
def handleMeta(meta):
    print("Meta is ")
    print(json.dumps(meta))
    type = meta['kind']
    if type == "INT":
        return handleInt(meta)
    if type == "PTR":
        return handlePtr(meta)
    if type == "ARRAY":
        return handleArray(meta)
    if type == "STRUCT":
        return handleStruct(meta)
    if type == "UNION":
        return handleUnion(meta)
    if type == "TYPEDEF":
        return handleTypedef(meta)
    if type == "FLOAT":
        return handleFloat(meta)
    if type == "ENUM" or type == 'ENUM64':
        return handleEnum(meta)
    else:
        raise Exception("Unknown type "+type)

def handleNotImplemented(meta):
    log.error("Type "+meta['type']+" is not implemented")
    return {}

def handleInt(meta):
    obj_deepcopy = copy.deepcopy(meta)
    ret = obj_deepcopy | {"expectedType": "int"}
    return ret

def handleEnum(meta):
    obj_deepcopy = copy.deepcopy(meta)
    ret = obj_deepcopy | {"expectedType": "enum"}
    return ret

def handleFloat(meta):
    obj_deepcopy = copy.deepcopy(meta)
    ret = obj_deepcopy | {"expectedType": "float"}
    return ret

def handlePtr(meta):
    subType = meta['type']
    return handleMeta(subType)

# Length of Array?
# https://docs.kernel.org/bpf/btf.html#btf-kind-array
# The above link suggests that arrays have a struct btf_array
# which contains number of elements. If this is populated then
# it can be extracted from the ELF by btf parsing eventually
# 
# And it seems like pahole and llvm both cannot support multi-dimensional
# array so that might be out of question for now
def handleArray(meta):
    subType = meta['type']
    variable_name = meta['name']
    member = handleMeta(subType)
    return { "expectedType": "array", 'variable_name': variable_name, "member": member}

def handleStruct(meta):
    members = meta['members']
    variable_name = meta['name']
    member_collection = []
    for member in members:
        m = {}
        m['variable_name'] = member['name']
        m = m | handleMeta(member['type'])
        member_collection.append(m)
    return {'expectedType': 'struct', 'variable_name': variable_name, 'members': member_collection}

def handleUnion(meta):
    members = meta['members']
    variable_name = meta['name']
    member_collection = []
    for member in members:
        m = {}
        m['variable_name'] = member['name']
        m = m | handleMeta(member['type'])
        member_collection.append(m)
    return {'expectedType': 'union', 'variable_name': variable_name, 'members': member_collection}

def handleFWD(meta):
    return handleNotImplemented(meta)

def handleTypedef(meta):
    subType = meta['type']
    return handleMeta(subType)

def handleVolatile(meta):
    return handleNotImplemented(meta)

def handleConst(meta):
    return handleNotImplemented(meta)

def handleRestrict(meta):
    return handleNotImplemented(meta)

def handleFunc(meta):
    return handleNotImplemented(meta)

def handleFuncProto(meta):
    return handleNotImplemented(meta)

def handleVAR(meta):
    return handleNotImplemented(meta)

def handleDATASEC(meta):
    return handleNotImplemented(meta)

def handleDeclTag(meta):
    return handleNotImplemented(meta)