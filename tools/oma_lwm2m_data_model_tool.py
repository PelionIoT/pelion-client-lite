#!/usr/bin/env python

## ----------------------------------------------------------------------------
## Copyright 2019 ARM Ltd.
##
## SPDX-License-Identifier: Apache-2.0
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
## ----------------------------------------------------------------------------

import sys
import types
import struct
from string import Formatter
from lxml import etree, objectify


TYPE_RESOURCE = 0xC0
TYPE_MULTIPLE_RESOURCE = 0x80
TYPE_RESOURCE_INSTANCE = 0x40
TYPE_OBJECT_INSTANCE = 0x0

MAX_TLV_LENGTH_SIZE = 3
MAX_TLV_ID_SIZE = 2
TLV_TYPE_SIZE = 1
ID8 = 0x0
ID16 = 0x20
LENGTH8 = 0x08
LENGTH16 = 0x10
LENGTH24 = 0x18


RES_CONSTS = {
    "": 0,
    "ID": 1,
    "Name": 2,
    "Operations": 30,
        "R": 31,
        "RW": 32,
        "W": 33,
        "E": 34,
        
    "MultipleInstances": 40,
        "Multiple": 41,
        "Single": 40,
        
    "Mandatory": 51,
        "Optional": 50,
        
    "Type": 60,
        "String": 61,
        "Integer": 62,
        "Float": 63,
        "Boolean": 64,
        "Opaque": 65,
        "Time": 66,
        "Objlnk": 67
}

OBJECT_STRUCT_FORMAT_STRING = \
"""    LWM2M_OBJECT_DEFINITION({objectid}, {MultipleInstances}, {Mandatory}, "{Name}", {resourcecount}, {resources})"""


RESOURCE_LIST_FORMAT_STRING = \
"""
const lwm2m_resource_meta_definition_t OMA_LWM2M_RESOURCE_DEFS_OBJECT_{}[] = {{
{}
}};
"""

RESOURCE_STRUCT_FORMAT_STRING = \
"""    LWM2M_RESOURCE_DEFINITION({resourceid}, {MultipleInstances}, {Mandatory}, {Operations}, {Type}, "{Name}")"""

OBJECT_ENUM_REVERSE_MAP = {
    "MultipleInstances": 
        {
            0: "LWM2M_OBJECT_SINGLE_INSTANCE",
            1: "LWM2M_OBJECT_MULTIPLE_INSTANCES"
        },
    "Mandatory":
        {
            0: "LWM2M_OBJECT_OPTIONAL",
            1: "LWM2M_OBJECT_MANDATORY"
        }
}

RESOURCE_ENUM_REVERSE_MAP = {
    "MultipleInstances": 
    {
        0: "LWM2M_RESOURCE_SINGLE_INSTANCE",
        1: "LWM2M_RESOURCE_MULTIPLE_INSTANCES"
    },
    "Mandatory":
    {
        0: "LWM2M_RESOURCE_OPTIONAL",
        1: "LWM2M_RESOURCE_MANDATORY"
    },
    "Operations":
    {
        0: "LWM2M_RESOURCE_OPERATIONS_NONE",
        1: "LWM2M_RESOURCE_OPERATIONS_R",
        2: "LWM2M_RESOURCE_OPERATIONS_RW",
        3: "LWM2M_RESOURCE_OPERATIONS_W",
        4: "LWM2M_RESOURCE_OPERATIONS_E"
    },
    "Type":
    {
        0: "LWM2M_RESOURCE_TYPE_NONE",
        1: "LWM2M_RESOURCE_TYPE_STRING",
        2: "LWM2M_RESOURCE_TYPE_INTEGER",
        3: "LWM2M_RESOURCE_TYPE_FLOAT",
        4: "LWM2M_RESOURCE_TYPE_BOOLEAN",
        5: "LWM2M_RESOURCE_TYPE_OPAQUE",
        6: "LWM2M_RESOURCE_TYPE_TIME",
        7: "LWM2M_RESOURCE_TYPE_OBJLNK"
    }    
    
}

def filter_resource_item(resource_item):
    # pick the elements we actually need and map all applicable values to the ranges used in the native side
    # see lwm2m_resource_static_definition_constants_t at lwm2m_registry_static.h for reference
    ret_item = {}
    res_id = int(resource_item.get("ID"))
    ret_item["Name"] = resource_item.Name
    ret_item["Operations"] = RES_CONSTS[resource_item.Operations] - RES_CONSTS["Operations"]
    if ret_item["Operations"] < 0:
        ret_item["Operations"] = 0
    ret_item["MultipleInstances"] = RES_CONSTS[resource_item.MultipleInstances] - RES_CONSTS["MultipleInstances"]
    
    ret_item["Mandatory"] = RES_CONSTS[resource_item.Mandatory] - RES_CONSTS["Optional"]
    ret_item["Type"] = RES_CONSTS[resource_item.Type] - RES_CONSTS["Type"]
    
    # map to none if not in valid range
    if ret_item["Type"] < 0:
        ret_item["Type"] = 0

    return res_id, ret_item
    

def filter_object_data(obj):
    ret_item = {}
    obj_id = int(obj.ObjectID)
    ret_item["Name"] = obj.Name
    ret_item["MultipleInstances"] = RES_CONSTS[obj.MultipleInstances] - RES_CONSTS["MultipleInstances"]
    ret_item["Mandatory"] = RES_CONSTS[obj.Mandatory] - RES_CONSTS["Optional"]

    return obj_id, ret_item


def main(args):

    with open(args.schema, "r") as schemafile:
        objdefs = []
        resdefs = []
        schema = etree.XMLSchema(file=schemafile)
        for xmlinput in args.input:
            with open(xmlinput, "r") as xmlfile:
                objectify.enable_recursive_str()
                parser = objectify.makeparser(schema=schema)
                LWM2M = objectify.parse(xmlfile, parser=parser)

                # pick only required resource fields from the spec
                object_resources = {}
                for resource_item in LWM2M.getroot().Object.Resources.Item:
                    res_id, filtered_res = filter_resource_item(resource_item)
                    object_resources[res_id] = filtered_res

                # record the offsets of each resource written to the array so that we can generate the index
                offsets = {}

                # first serialized "thing" in the actual data is the object metadata
                obj_id, obj_items = filter_object_data(LWM2M.getroot().Object)

                # map the values back to enum
                for obj_item_key, obj_item in obj_items.items():
                    if obj_item_key in OBJECT_ENUM_REVERSE_MAP:
                        obj_items[obj_item_key] = OBJECT_ENUM_REVERSE_MAP[obj_item_key][obj_item]
                obj_items["objectid"] = obj_id
                obj_items["namelength"] = len(str(obj_items["Name"]))
                obj_items["resourcecount"] = len(object_resources.items())

                # .. followed by the resource metadata
                struct_list = []
                for res_id, res in object_resources.items():
                    for res_item_key, res_item in res.items():
                        if res_item_key in RESOURCE_ENUM_REVERSE_MAP:
                            res[res_item_key] = RESOURCE_ENUM_REVERSE_MAP[res_item_key][res[res_item_key]]

                    res["resourceid"] = res_id
                    res["namelength"] = len(str(res["Name"]))

                    struct_list.append(Formatter().vformat(RESOURCE_STRUCT_FORMAT_STRING, None, res))


                obj_items["resources"] = "OMA_LWM2M_RESOURCE_DEFS_OBJECT_" + str(obj_id)
                resdefs.append(RESOURCE_LIST_FORMAT_STRING.format(obj_id, ",\n".join(struct_list)))

                objdefs.append(Formatter().vformat(OBJECT_STRUCT_FORMAT_STRING, None, obj_items))

        # export the generated object/resource structures to the C file using a template
        if args.coutput and args.ctemplate:
            with open(args.coutput, "w") as coutputfile:
                with open(args.ctemplate, "r") as ctemplatefile:
                    ctemplate = ctemplatefile.read()
                    coutputfile.write(ctemplate.replace("%%OBJDEFS%%", ",\\\n".join(objdefs)).replace("%%RESDEFS_LIST%%", "\n".join(resdefs)))


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--schema', help="XML Schema file to use", action="store", default="LWM2M.xsd")
    parser.add_argument('-i', '--input', help="OMA LWM2M Object spec XML file to use", action="store", nargs="+")
    parser.add_argument('-o', '--output', help="Output file for Object spec data", action="store")
    parser.add_argument('-c', '--coutput', help="C source output file for Object spec data", action="store")
    parser.add_argument('-m', '--ctemplate', help="C source template file for Object spec data", action="store")
    
    args = parser.parse_args()
    main(args)
