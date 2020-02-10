#################################################################################
#  Copyright 2016, 2017 ARM Ltd.
#  
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#      http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#################################################################################

macro(SET_COMPILER_DBG_RLZ_FLAG flag value)
    SET(${flag}_DEBUG "${${flag}_DEBUG} ${value}")
    SET(${flag}_RELEASE "${${flag}_RELEASE} ${value}")
#enable this if for debugging
if (0)
 message("flag = ${flag}")
 message("value = ${value}")
 message("MY_C_FLAGS_RELEASE2 = ${CMAKE_C_FLAGS_RELEASE}")
endif(0) # comment end
endmacro(SET_COMPILER_DBG_RLZ_FLAG)

# EXECUTABLE EXTENSION
SET (CMAKE_EXECUTABLE_SUFFIX "")

set(CMAKE_ASM_OUTPUT_EXTENSION ".o")
set(CMAKE_C_OUTPUT_EXTENSION ".o")
set(CMAKE_DEPFILE_FLAGS_C "--depend-target=<OBJECT> --depend=<DEPFILE> --depend_single_line --no_depend_system_headers")
set(CMAKE_CXX_OUTPUT_EXTENSION ".o")
set(CMAKE_DEPFILE_FLAGS_CXX "--depend-target=<OBJECT> --depend=<DEPFILE> --depend_single_line --no_depend_system_headers")

SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_CXX_FLAGS "")

# Release/Debug common
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "-c")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "--apcs=interwork")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "--split_sections")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "--library_interface=armcc")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "--library_type=standardlib")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "--c99")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "--diag_suppress=66,177,1296,186")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "--gnu")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "-D__EVAL")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "-D__MICROLIB")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS "-DPRINTF_ADVANCED_ENABLE=1")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_C_FLAGS " --via=${CMAKE_SOURCE_DIR}/include_file.txt")



###################################################### CXX FLAGS #######################################################

# Release/Debug specific
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG" CACHE INTERNAL "cxx compiler flags release")

SET_COMPILER_DBG_RLZ_FLAG (CMAKE_CXX_FLAGS " --via=${CMAKE_SOURCE_DIR}/include_file.txt")


# Release/Debug common
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "-c")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "--cpp")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "--apcs=interwork")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "--split_sections")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "--library_interface=armcc")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "--library_type=standardlib")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "--diag_suppress=66,177,1296,186")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "--gnu")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "-D__EVAL")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "-D__MICROLIB")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "-DPRINTF_ADVANCED_ENABLE=1")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_CXX_FLAGS "-D__STDC_FORMAT_MACROS")


# Release/Debug common
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--library_type=microlib")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--nodebug")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--diag_suppress 6314,6238")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--strict")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--remove")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--summary_stderr")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--info summarysizes")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--info sizes")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--info totals")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--info unused")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--info veneers")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--map")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--xref")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--callgraph")
SET_COMPILER_DBG_RLZ_FLAG(CMAKE_EXE_LINKER_FLAGS "--symbols")


# TOOLCHAIN EXTENSION
IF(WIN32)
    SET(TOOLCHAIN_EXT ".exe")
ELSE()
    SET(TOOLCHAIN_EXT "")
ENDIF()

# TOOLCHAIN_DIR
SET(TOOLCHAIN_DIR $ENV{ARMCC_DIR})
STRING(REGEX REPLACE "\\\\" "/" TOOLCHAIN_DIR "${TOOLCHAIN_DIR}")

IF(NOT TOOLCHAIN_DIR)
    MESSAGE(FATAL_ERROR "***Please set ARMCC_DIR in environment variables***")
ENDIF()

MESSAGE(STATUS "TOOLCHAIN_DIR: " ${TOOLCHAIN_DIR})

SET(TOOLCHAIN_BIN_DIR ${TOOLCHAIN_DIR}/bin)
SET(TOOLCHAIN_INC_DIR ${TOOLCHAIN_DIR}/include)
SET(TOOLCHAIN_LIB_DIR ${TOOLCHAIN_DIR}/lib)

SET(CMAKE_SYSTEM_NAME Generic)
SET(CMAKE_SYSTEM_PROCESSOR arm)

if(CMAKE_VERSION VERSION_LESS "3.6.0")
    INCLUDE(CMakeForceCompiler)
    CMAKE_FORCE_C_COMPILER(${TOOLCHAIN_BIN_DIR}/armcc${TOOLCHAIN_EXT} ARMCC)
    CMAKE_FORCE_CXX_COMPILER(${TOOLCHAIN_BIN_DIR}/armcc${TOOLCHAIN_EXT} ARMCC)
else()
    # linking an executable for cmake's try_compile tests won't work for bare
    # metal, so link a static library instead:
    SET(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")
    SET(CMAKE_C_COMPILER ${TOOLCHAIN_BIN_DIR}/armcc${TOOLCHAIN_EXT} CACHE FILEPATH "C compiler")
    SET(CMAKE_CXX_COMPILER ${TOOLCHAIN_BIN_DIR}/armcc${TOOLCHAIN_EXT} CACHE FILEPATH "C++ compiler")
endif()

SET(CMAKE_LINKER "${TOOLCHAIN_BIN_DIR}/armlink${TOOLCHAIN_EXT}" CACHE FILEPATH "linker")
SET(CMAKE_AR "${TOOLCHAIN_BIN_DIR}/armar${TOOLCHAIN_EXT}" CACHE FILEPATH "archiver")
SET(CMAKE_ASM_COMPILER "${TOOLCHAIN_BIN_DIR}/armasm${TOOLCHAIN_EXT}" CACHE FILEPATH "assembler")
SET(CMAKE_FROMELF "${TOOLCHAIN_BIN_DIR}/fromelf${TOOLCHAIN_EXT}" CACHE FILEPATH "fromelf tool")


macro(ELF_TO_BIN target_name target_dir)
    add_custom_command(
        TARGET ${target_name}.elf
        POST_BUILD
        COMMAND "${CMAKE_FROMELF}" --bincombined ${target_dir}/${target_name}.elf --output ${target_dir}/${target_name}.bin
        COMMENT "converting to .bin"
        VERBATIM
    )
endmacro(ELF_TO_BIN)

###################################################### ASM FLAGS #######################################################

SET(CMAKE_ASM_COMPILE_OBJECT "<CMAKE_ASM_COMPILER> <FLAGS> --xref --width=100 --list <OBJECT>.lst -o <OBJECT> <SOURCE>")

# Release/Debug specific
SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE}" CACHE INTERNAL "asm compiler flags release")
SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -g --cpreproc_opts \"-DDEBUG\"" CACHE INTERNAL "asm compiler flags debug")

###################################################### C FLAGS #########################################################

# Release/Debug specific
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG" CACHE INTERNAL "c compiler flags release")
SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g -DDEBUG" CACHE INTERNAL "c compiler flags debug")


###################################################### AR FLAGS ########################################################

SET(CMAKE_C_CREATE_STATIC_LIBRARY "<CMAKE_AR> --create -cr <TARGET> <LINK_FLAGS> <OBJECTS>")
SET(CMAKE_CXX_CREATE_STATIC_LIBRARY "<CMAKE_AR> --create -cr <TARGET> <LINK_FLAGS> <OBJECTS>")

###################################################### LINKER FLAGS ####################################################

SET(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <LINK_LIBRARIES> <OBJECTS> -o <TARGET> --list <TARGET_BASE>.map")
SET(CMAKE_CXX_LINK_EXECUTABLE "<CMAKE_LINKER> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <LINK_LIBRARIES> <OBJECTS> -o <TARGET> --list <TARGET_BASE>.map")

# Release/Debug specific
SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE}" CACHE INTERNAL "linker flags release")
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}" CACHE INTERNAL "linker flags debug")


########################################################################################################################


SET(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_DIR} ${EXTRA_FIND_PATH})
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


SET(TOOLCHAIN_FLAGS_FILE "${CMAKE_SOURCE_DIR}/../pal-platform/Toolchain/ARMCC/ARMCC-flags.cmake" CACHE INTERNAL "linker flags file")

MESSAGE(STATUS "BUILD_TYPE: " ${CMAKE_BUILD_TYPE})
