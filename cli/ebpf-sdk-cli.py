##
# Simple python based bpf map CRUD tool 
#
# Author: Dushyant Behl <dushyantbehl@in.ibm.com>

import json
import copy
import argparse
import logging

logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-4s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
log = logging.getLogger(__name__)

def userInput(msg, expectedType=None):
    dst = input(msg+'\n')
    if expectedType is not None:
        if type(dst) != expectedType:
            raise Exception("expectedType "+expectedType+" input "+type(dst))
    return dst

def loadMapPaths(maps):
    log.info("First we need to know where maps are")
    for map in maps:
        log.info("Please tell the pinned location of the map - "+map['name'])
        map['path'] = userInput("Please tell the pinned location of the map - "+map['name'], str)
    log.info("Thanks")
    log.info(json.dumps(maps, indent=1))

def main(args):
    log.info("Welcome to ebpf-client-sdk-cli")
    try:
        #Check and open enriched btf file.
        with open(args.parsed_btf, 'r') as btf_file:
            btf = json.loads(btf_file.read())
        maps = btf['maps']
            
        op = args.op
        if op == 'create':
            log.info('create map entry for map')
        elif op == 'read':
            log.info('read map entry from map')
        elif op == 'update':
            log.info('update map entry for map')
        elif op == 'delete':
            log.info('delete map entry for map')
        elif op == 'enrich':
            loadMapPaths(maps)
            log.info("added map path info. updating file")
            obj = {}
            obj['maps'] = maps
            with open(args.parsed_btf, 'w') as btf_file:
                btf_file(json.dumps(obj))
        else:
            log.error("Unknown operation")

    except Exception as e:
        log.error("Exception when running executor "+str(e))
        raise Exception(str(e))

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='ebpf sdk cli tool')
    argparser.add_argument('--parsed_btf', dest='parsed_btf', help="enriched btf file (in json format) output from bpfmap-info-extractor", required=True)
    argparser.add_argument('--op', dest='op', help='enrich/create/read/update/delete', required=True)
    args = argparser.parse_args()
    main(args)