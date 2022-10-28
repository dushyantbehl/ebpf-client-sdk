import json
import copy
import argparse
import logging

logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-4s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
log = logging.getLogger(__name__)

typeIDToTypeTable = {}

def parseRecursiveType(typeID):
    _type = {}
    raw_type = typeIDToTypeTable[typeID]

    _type['name'] = raw_type['name']
    _type['kind'] = raw_type['kind']

    if 'type_id' in  raw_type: # recurse
        _type['type'] = parseRecursiveType(raw_type['type_id'])
    elif 'members' in raw_type: # check if the type has members.
        members = raw_type['members']
        _members = []
        for member in members:
            _member = {}
            _member['name'] = member['name']
            _member['type'] = parseRecursiveType(member['type_id'])
            _members.append(_member)
        _type['members'] = _members
    else:
        # no members and no type_id, this is a basic type so copy the definition.
        _type['type'] = copy.deepcopy(raw_type)

    return _type

def parseMapType(typeID, map):
    # first we check the map name from map type.
    base_type = typeIDToTypeTable[typeID]
    map['name'] = base_type['name']
    maptypeid = base_type['type_id']

    # Now its key & value sub types.
    maptype = typeIDToTypeTable[maptypeid]
    if (maptype['kind'] != 'STRUCT'):
        raise Exception("Map type kind %s is not a STRUCT" % maptype['kind'])
    members = maptype['members']

    # parse the sub types of this map in a depth first search fashion
    # collect the sub type info
    for member in members:
        if member['name'] == 'key' or member['name'] == 'value':
            map[member['name']] = parseRecursiveType(member['type_id'])

    return map

def main(args):
    try:
        #Check and open btf file.
        with open(args.btf, 'r') as btf_file:
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
            if type['kind'] == 'DATASEC' and type['name'] == '.maps':
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

        parsed = {}
        parsed['maps'] = maps

        #pretty print the output
        log.info('parsed btf - ')
        print(json.dumps(parsed, indent = 2))

    except Exception as e:
        log.error("Exception when running executor "+str(e))
        raise Exception(str(e))


if __name__ == "__main__":

    argparser = argparse.ArgumentParser(description='BTF parser')
    argparser.add_argument('--btf', dest='btf', help="btf file (in json format)", required=True)
    args = argparser.parse_args()
    main(args)