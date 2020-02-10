
#################################################################################
#  Copyright 2016-2018 ARM Ltd.
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

INCLUDE(CMakeForceCompiler)

#This file defines needed options for native GCC compiler.

######### Configure all Options here ##########
################################################

# TOOLCHAIN EXTENSION
IF(WIN32)
    SET(TOOLCHAIN_EXT ".exe")
ELSE()
    SET(TOOLCHAIN_EXT "")
ENDIF()

# EXECUTABLE EXTENSION
SET (CMAKE_EXECUTABLE_SUFFIX "")

# TOOLCHAIN_DIR AND NANO LIBRARY
SET(TOOLCHAIN_DIR $ENV{GCC_DIR})
STRING(REGEX REPLACE "\\\\" "/" TOOLCHAIN_DIR "${TOOLCHAIN_DIR}")

IF(NOT TOOLCHAIN_DIR)
    set(TOOLCHAIN_DIR "/usr")
ENDIF()


# TARGET_TRIPLET - none in the case of native compilation
SET(TARGET_TRIPLET "")

SET(TOOLCHAIN_BIN_DIR ${TOOLCHAIN_DIR}/bin)
SET(TOOLCHAIN_INC_DIR ${TOOLCHAIN_DIR}/include)
SET(TOOLCHAIN_LIB_DIR ${TOOLCHAIN_DIR}/lib)

MESSAGE(STATUS "TOOLCHAIN_DIR: " ${TOOLCHAIN_DIR})
MESSAGE(STATUS "TOOLCHAIN_BIN_DIR: " ${TOOLCHAIN_BIN_DIR})
MESSAGE(STATUS "TOOLCHAIN_INC_DIR: " ${TOOLCHAIN_INC_DIR})
MESSAGE(STATUS "TOOLCHAIN_LIB_DIR: " ${TOOLCHAIN_LIB_DIR})
SET(CMAKE_SYSTEM_NAME Generic)
#SET(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER ${TOOLCHAIN_BIN_DIR}/gcc${TOOLCHAIN_EXT} )
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_BIN_DIR}/g++${TOOLCHAIN_EXT} )
SET(CMAKE_ASM_COMPILER ${TOOLCHAIN_BIN_DIR}/gcc${TOOLCHAIN_EXT})

SET(CMAKE_OBJCOPY ${TOOLCHAIN_BIN_DIR}/objcopy CACHE INTERNAL "objcopy tool")
# SET(CMAKE_OBJCOPY ${TOOLCHAIN_DIR}/${TARGET_TRIPLET}/bin/objcopy CACHE INTERNAL "objcopy tool")
SET(CMAKE_OBJDUMP ${TOOLCHAIN_BIN_DIR}/objdump CACHE INTERNAL "objdump tool")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 " CACHE INTERNAL "c compiler flags release")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 " CACHE INTERNAL "cxx compiler flags release")   
SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE}" CACHE INTERNAL "asm compiler flags release")
SET(CMAKE_EXE_LINKER_FLAGS_RELESE "${CMAKE_EXE_LINKER_FLAGS_RELESE}" CACHE INTERNAL "linker flags release")

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g" CACHE INTERNAL "c compiler flags debug")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g" CACHE INTERNAL "cxx compiler flags debug")
SET(CMAKE_ASM_FLAGS_DEBUG "${CMAKE_ASM_FLAGS_DEBUG} -g" CACHE INTERNAL "asm compiler flags debug")
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}" CACHE INTERNAL "linker flags debug")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 " CACHE INTERNAL "c compiler flags release")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 " CACHE INTERNAL "cxx compiler flags release")
SET(CMAKE_ASM_FLAGS_RELEASE "${CMAKE_ASM_FLAGS_RELEASE}" CACHE INTERNAL "asm compiler flags release")
SET(CMAKE_EXE_LINKER_FLAGS_RELESE "${CMAKE_EXE_LINKER_FLAGS_RELESE}" CACHE INTERNAL "linker flags release")

#SET(TOOLCHAIN_FLAGS_FILE "${CMAKE_SOURCE_DIR}/../pal-platform/Toolchain/GCC/GCC-flags.cmake" CACHE INTERNAL "linker flags file")
#todo would be cleaner if we could include from the same directory where this file is...
#include("${CMAKE_CURRENT_LIST_DIR}/GCC-flags.cmake")

#start copy paste
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

########### COMPILER FLAGS  ###########

SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-D__STARTUP_CLEAR_BSS")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-mcpu=${CPU}")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-Wall")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-mfloat-abi=hard")
# Floating point support

SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-mthumb")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-fno-common")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-ffunction-sections")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-fdata-sections")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-ffreestanding")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-fno-builtin")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-mapcs")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_ASM_FLAGS "-std=c99")

# Debug specific
SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
if (PAL_GCOV_SUPPORT)
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0  -fprofile-arcs -ftest-coverage")
endif ()

# Board specific

SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-Wall")
# Board specific
if (${CPU} MATCHES "x86_64")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-m32")
endif ()
if (${CPU} MATCHES "cortex-m4")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-mcpu=${CPU}")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-mfloat-abi=hard")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-mapcs")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-mthumb")
endif()

SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-MMD")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-MP")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-fno-common")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-ffunction-sections")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-fdata-sections")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-ffreestanding")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-fno-builtin")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "-std=gnu99")


########### Release specific ###########
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNDEBUG")
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")
######################################

########### LINKER FLAGS  ###########
#
#
#####################################

########### DEBUG ###########
# Debug specific
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -g")
if (PAL_GCOV_SUPPORT)
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -g -O0 -lgcov -fprofile-arcs")
endif ()

########### RELEASE ###########

if (${CPU} MATCHES "x86_64")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-m32")
elseif (${CPU} MATCHES "cortex-m4")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-mcpu=${CPU}")     
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-mfloat-abi=hard")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "--specs=nano.specs")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-mthumb")
    SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-mapcs")
endif()

SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-Wall")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-fno-common")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-ffunction-sections")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-fdata-sections")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-ffreestanding")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-fno-builtin")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-Xlinker")
SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "--gc-sections")

if (PAL_MEMORY_STATISTICS)
	SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-Wl,--wrap=malloc")
	SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-Wl,--wrap=free")
	SET_COMPILER_DBG_RLZ_FLAG (CMAKE_EXE_LINKER_FLAGS "-Wl,--wrap=calloc")
	add_definitions("-DPAL_MEMORY_STATISTICS")
endif()

# This is because of mbedTLS is removing all debug and release compilation flags
# but keeping the global common flags so need to set all of them... no harm is done
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} @${CMAKE_SOURCE_DIR}/include_file.txt")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} @${CMAKE_SOURCE_DIR}/include_file.txt")
#SET_COMPILER_DBG_RLZ_FLAG (CMAKE_C_FLAGS "@${CMAKE_SOURCE_DIR}/include_file.txt")
#SET_COMPILER_DBG_RLZ_FLAG (CMAKE_CXX_FLAGS "@${CMAKE_SOURCE_DIR}/include_file.txt")

MESSAGE(STATUS "BUILD_TYPE: " ${CMAKE_BUILD_TYPE})

#end copy paste 



########### DEBUG ###########
# Debug specific
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -g")
#########

SET(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_DIR}/${TARGET_TRIPLET} ${EXTRA_FIND_PATH})
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM BOTH)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)

MESSAGE(STATUS "BUILD_TYPE: " ${CMAKE_BUILD_TYPE})

