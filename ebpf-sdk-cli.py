##
# Simple python based bpf map CRUD tool 
#
# Author: Dushyant Behl <dushyantbehl@in.ibm.com>

import os
import json
import argparse
import logging
import time
import yaml

import btf

logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-4s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
log = logging.getLogger(__name__)

def execute_blocking_call(cmd, dirname=None):
    if dirname is not None:
        os.chdir(dirname)
    log.debug("%s" % (cmd))
    exitcode = os.system(cmd)
    return exitcode

encoding = 'yaml'
tmpfilename='/tmp/ebpf-sdk-cli-input.'+encoding

def askUserForValues(key, value):
    #key['_comment'] = 'Fill the key according to the json in the input field'
    obj = {'key': key}
    if value is not None:
        #value['_comment'] = 'Fill the value according to the json in the input field'
        obj['value'] = value

    obj['byteOrder'] = "reversed"

    with open(tmpfilename, 'w') as f:
        # convert to yaml
        obj = yaml.safe_dump(obj, indent=1, sort_keys=False)
        f.write(obj)

    openEditorCMD = 'vim '+tmpfilename
    execute_blocking_call(openEditorCMD)

    # Assume values are filled in.
    f =  open(tmpfilename, 'r')
    content = f.read()
    userProvided = yaml.safe_load(content)
    #log.info('After user input - ')
    #log.info(yaml.safe_dump(userProvided, indent=1, sort_keys=False))
    f.close()

    flatten_key = userProvided['key']
    if value is not None:
        flatten_value = userProvided['value']
    else:
        flatten_value = None

    try:
        byteOrder = userProvided['byteOrder']
    except:
        byteOrder = "reversed"
        pass

    return {
        "flatten_key": flatten_key,
        "flatten_value": flatten_value,
        "byteOrder": byteOrder
    }

def getUserInput(msg, expectedType=None):
    dst = input(msg+'\n')
    if expectedType is not None:
        try:
            converted = expectedType(dst)
            return converted
        except ValueError:
            raise Exception("expectedType "+str(expectedType)+" input "+str(type(dst)))
    return dst

def loadMapPaths(maps):
    log.info("First we need to know where maps are")
    for map in maps:
        log.info("Please tell the pinned location of the map - "+map['name'])
        map['path'] = getUserInput("Please tell the pinned location of the map - "+map['name'], str)
    log.info("Thanks")
    log.info(json.dumps(maps, indent=1))

def convertToHexByteString(bytes):
    hex_string = bytes.hex()
    ret = ""
    i = 0
    while i<len(hex_string):
        b = hex_string[i:i+2]
        ret += "0x"+b+" "
        i+=2
    return ret

def doCreateOrUpdate(map, key_bytes, value_bytes):
    key = convertToHexByteString(key_bytes)
    value = convertToHexByteString(value_bytes)

    cmd = 'bpftool map update pinned '+map['path'] + " "
    cmd += 'key '+key+' value '+value
    return execute_blocking_call(cmd)

def doRead(map, key_bytes):
    key = convertToHexByteString(key_bytes)
    cmd = 'bpftool map lookup pinned '+map['path'] + " "
    cmd += 'key '+key
    return execute_blocking_call(cmd)

def doDelete(map, key_bytes):
    key = convertToHexByteString(key_bytes)
    cmd = 'bpftool map delete pinned '+map['path'] + " "
    cmd += 'key '+key
    return execute_blocking_call(cmd)

def doCRUD(op, maps, args):
    m = None
    if args.map is not None:
        map_name = args.map
        log.info('map name passed is '+map_name)
        for m in maps:
            if m['name'] == map_name:
                map = m
    if m is None:
        log.info("First we need to know which map to use")
        l = len(maps)
        for id in range(l):
            log.info(str(id)+": "+maps[id]['name'])
        idToUse = getUserInput("Please enter id of the map to use - ", int)
        if idToUse<0 or idToUse>l:
            log.error("Uknown input try again")
            os._exit(1)
        map = maps[idToUse]

    log.info('Selected map is '+map['name'])

    flatten_key = map['key']['flatten']
    if (op == 'create' or op == 'update'):
        flatten_value = map['value']['flatten']
    else:
        flatten_value = None

    userProvided = askUserForValues(key=flatten_key, value=flatten_value)
    # refresh values
    flatten_key = userProvided['flatten_key']
    flatten_value = userProvided['flatten_value']
    byteOrder = userProvided['byteOrder']
    log.info('Loaded user input ')

    raw_key = btf.generateRawValue(flatten_key, byteOrder=byteOrder)
    raw_value = btf.generateRawValue(flatten_value, byteOrder=byteOrder)

    if op == 'create' or op == 'update':
        log.info('Going to perform op '+op)
        ret = doCreateOrUpdate(map, key_bytes=raw_key, value_bytes=raw_value)
    elif op == 'read':
        ret = doRead(map, key_bytes=raw_key)
    elif op == 'delete':
        ret = doDelete(map, key_bytes=raw_key)

    log.info('op returned %d', ret)

def main(args):
    log.info("Welcome to ebpf-client-sdk-cli")
    try:
        #Check and open enriched btf file.
        with open(args.parsed_btf, 'r') as btf_file:
            btf = json.loads(btf_file.read())
        maps = btf['maps']

        op = args.op
        if (op == 'create' or op == 'read' or
            op == 'update' or op == 'delete'):
            log.info(op+' map entry for map')
            doCRUD(op, maps, args)
        elif op == 'enrich':
            loadMapPaths(maps)
            log.info("added map path info. updating file")
            obj = {}
            obj['maps'] = maps
            with open(args.parsed_btf, 'w') as btf_file:
                btf_file.write(json.dumps(obj))
        else:
            log.error("Unknown operation")

    except Exception as e:
        log.error("Exception when running executor "+str(e))
        raise Exception(str(e))

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='ebpf sdk cli tool')
    argparser.add_argument('--parsed_btf', dest='parsed_btf', help="enriched btf file (in json format) output from bpfmap-info-extractor", required=True)
    argparser.add_argument('--op', dest='op', help='enrich/create/read/update/delete', required=True)
    argparser.add_argument('--map', dest='map', help='map name to use', required=False)
    argparser.add_argument('--encoding', dest='encoding', help='yaml/json to use', default='yaml', required=False)
    args = argparser.parse_args()
    main(args)