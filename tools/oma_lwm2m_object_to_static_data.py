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

"""
Generates a C file containing a concatenated version of given Object definition files in binary format.

The oma_lwm2m_data_model_tool.py python script should be used to generate the Object definition files.
"""

import sys
import types
import struct

# @param1 object data size
# @param2 object data array
OBJECT_DEF_FORMAT_STR = "const uint8_t OMA_LWM2M_OBJECT_DEF_DATA[{}] = {{ {} }};\r\n"

# @param1 object id
# @param2 object size
OBJECT_DEF_SIZE_FORMAT_STR = "#define OMA_LWM2M_OBJECT_DEF_DATA_{}_SIZE {}\r\n"

# @param1 object id
# @param2 object offset
OBJECT_DEF_OFFSET_FORMAT_STR = "#define OMA_LWM2M_OBJECT_DEF_DATA_{}_OFFSET {}\r\n"

# @param1 object id
# @param2 object data size
# @param3 object data offset in OMA_LWM2M_OBJECT_DEF_DATA
OBJECT_DEFS_FORMAT_STR = "\r\n    {{ {}, OMA_LWM2M_OBJECT_DEF_DATA_{}_SIZE, OMA_LWM2M_OBJECT_DEF_DATA_{}_OFFSET }}"

def main(args):
    # generate C file with correct constant values
    if args.template and args.input and args.output:
        with open(args.template, "r") as source_template_file:
            with open(args.output, "w") as source_file:
                objdefs = {}
                for input_filename in args.input:
                    with open(input_filename, "r") as input_file:
                        obj_def_data = input_file.read()
                        obj_id = struct.unpack("!H", obj_def_data[:2])[0]
                        
                        obj_def_arr = ', '.join('0x{:02x}'.format(x) for x in bytearray(obj_def_data))
                        
                        objdefs[obj_id] = (len(obj_def_data), obj_def_arr)
                
                template = source_template_file.read()
                obj_def_str_array = []
                obj_def_size_array = []
                obj_def_offset_array = []
                obj_defs_str_array = []
                objdef_offset = 0

                # append each object definition to the static array and store the offsets and sizes for struct initialization
                for obj_id, (objdef_len, objdef) in objdefs.items():

                    obj_def_str_array += [objdef]

                    obj_def_size_array += [OBJECT_DEF_SIZE_FORMAT_STR.format(obj_id, objdef_len)]
                    obj_def_offset_array += [OBJECT_DEF_OFFSET_FORMAT_STR.format(obj_id, objdef_offset)]

                    obj_defs_str_array += [OBJECT_DEFS_FORMAT_STR.format(obj_id, obj_id, obj_id)]
                    objdef_offset += objdef_len



                source_file.write((template.replace("%%OBJDEFS%%", OBJECT_DEF_FORMAT_STR.format(objdef_offset, ", ".join(obj_def_str_array)))
                                           .replace("%%OBJDEFSIZES%%", "".join(obj_def_size_array))
                                           .replace("%%OBJDEFOFFSETS%%", "".join(obj_def_offset_array))
                                           .replace("%%OBJECTDEF_LIST%%", ",".join(obj_defs_str_array))))


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help="OMA LWM2M Object spec def file to use", action="store", nargs="+")
    parser.add_argument('-o', '--output', help="Output file for Object spec static data (C source file)", action="store")
    parser.add_argument('-t', '--template', help="Template file for C source file", action="store")

    
    args = parser.parse_args()
    main(args)
