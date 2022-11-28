##
# Parse BTF json created by command
# bpftool btf dump -p file <btf-file.o>
# 
# Generate a parsed json containing map and key and flattened btf objects
# which is used by cli to perform CRUD over bpf maps.
#
# Author: Dushyant Behl <dushyantbehl@in.ibm.com>

import os
import json
import copy
import argparse
import logging
import lief

import btf # local file

logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-4s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
log = logging.getLogger(__name__)

typeIDToTypeTable = {}

def parseRecursiveType(typeID):
    type_obj = {}
    raw_type = typeIDToTypeTable[typeID]

    type_obj['name'] = raw_type['name']
    type_obj['kind'] = raw_type['kind']

    if 'type_id' in  raw_type: # recurse
        type_obj['type'] = parseRecursiveType(raw_type['type_id'])
    elif 'members' in raw_type: # check if the type has members.
        members = raw_type['members']
        _members = []
        for member in members:
            _member = {}
            _member['name'] = member['name']
            _member['type'] = parseRecursiveType(member['type_id'])
            _members.append(_member)
        type_obj['members'] = _members
    else:
        # no members and no type_id, this is a basic type so copy the definition.
        raw_type_deepcopy = copy.deepcopy(raw_type)
        type_obj = type_obj | raw_type_deepcopy

    return type_obj

def parseMapType(typeID, map):
    #print("Parsing typeid "+str(typeID))

    # first we check the map name from map type.
    base_type = typeIDToTypeTable[typeID]
    name = base_type['name']
    maptypeid = base_type['type_id']

    map['name'] = name
    #print("Map name is "+name+" typeid is "+str(maptypeid))

    # Now its key & value sub types.
    maptype = typeIDToTypeTable[maptypeid]
    if (maptype['kind'] != 'STRUCT'):
        raise Exception("Map type kind %s is not a STRUCT" % maptype['kind'])
    members = maptype['members']

    #print("map members are - "+json.dumps(members, indent=1))

    # parse the sub types of this map in a depth first search fashion
    # collect the sub type info
    for member in members:
        if member['name'] == 'key' or member['name'] == 'value':
            map[member['name']] = parseRecursiveType(member['type_id'])

    return map

# Not implemented.
def enrichMapType(maps, bpf):
    try:
        # Get map section details.
        bpfelf = lief.parse(bpf)
        maps_section = bpfelf.get_section("maps")
        maps_offset = maps_section.file_offset
        maps_size = maps_section.original_size
    except Exception as e:
        log.error("Exception when running map enrichment module "+str(e))
        raise Exception(str(e))
    return 

def getBTFFromELF(elf):
    tmp_btf_dump_file = "/tmp/bpf-client-sdk-raw-btf-dump.json"
    bpftool_dump_cmd = 'bpftool btf dump file '+elf+' -p' + ' > '+tmp_btf_dump_file
    log.info('Executing cmd: '+bpftool_dump_cmd)
    exitcode = os.system(bpftool_dump_cmd)
    if exitcode != 0:
        raise Exception("Error "+str(exitcode)+" while running the btf extraction.")
    return tmp_btf_dump_file

def main(args):
    try:
        # one of elf or btf should be set.
        if args.elf != None:
            log.info("Supplied bpf object, extracting raw btf")
            btf_json_file = getBTFFromELF(args.elf)
        elif args.btf != None:
            log.info("Supplied raw btf, using as is")
            btf_json_file = args.btf
        else:
            err_args = 'Either --elf or --btf should be supplied'
            log.error(err_args)
            raise Exception(err_args)

        #Check and open btf file.
        with open(btf_json_file, 'r') as btf_file:
            rawBTF = json.loads(btf_file.read())

        # types is an array of the types.
        types = rawBTF['types']

        global typeIDToTypeTable
        for type in types:
            id = type['id']
            typeIDToTypeTable[id] = type

        # Maps subtype is with
        # kind: DATASEC
        # name: .maps
        for type in types:
            if (type['kind'] == 'DATASEC' and
                (type['name'] == '.maps' or 
                 type['name'] == 'maps')):
                maps_datasec = type
                break

        # This array contains differnet map variables in btf
        map_vars = maps_datasec['vars']

        maps = []
        for var in map_vars:
            map = {}
            map['size'] = var['size']
            parseMapType(var['type_id'], map)
            maps.append(map)

        for map in maps:
            if 'key' not in map or 'value' not in map:
                # Some maps don't even have any key/value
                # Not sure what do we even do with them
                continue
            flatten_key = btf.flattenBTF(map['key'])
            flatten_value = btf.flattenBTF(map['value'])
            map['key']['flatten'] = flatten_key
            map['value']['flatten'] = flatten_value

        parsed = {}
        parsed['maps'] = maps

        content = json.dumps(parsed, indent=1)
        if args.parsed_btf is not None:
            log.info('output file - '+args.parsed_btf)
            with open (args.parsed_btf, 'w+') as f:
                f.write(content)
            log.info('parsed btf is dumped to '+args.parsed_btf+" which is to be used as input to cli")
        else:
            log.info("output file --parsed_btf is not set.")
            log.info("dumping parsed content to stdout - ")
            log.info("\n"+content)

    except Exception as e:
        log.error("Exception when running executor "+str(e))
        raise Exception(str(e))


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='BPF Map info parser')
    argparser.add_argument('--elf', dest='elf', help="bpf object file (elf format)", required=False)
    argparser.add_argument('--btf', dest='btf', help="btf file (in json format)", required=False)
    argparser.add_argument('--parsed_btf', dest='parsed_btf', help="output to be generated...parsed btf file", required=False)
    argparser.add_argument('--bpf', dest='bpf', help="bpf object file to parse. bpf elf format.", required=False)
    args = argparser.parse_args()
    main(args)