# CMakeLists.txt for LIBLBER in OpenLDAP
# This work is part of OpenLDAP Software <http://www.openldap.org/>.
# Copyright 1998-2022 The OpenLDAP Foundation.
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
# A copy of this license is available in the file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.

cmake_minimum_required(VERSION 3.10)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../config.cmake)

project(LIBLBER LANGUAGES C)

# List of source files
if(WIN32)
    set(PLAT_SRCS nt_err.c)
endif()

set(SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/ldap_config.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/portable.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/ldap_features.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/lber_types.h
    assert.c decode.c encode.c io.c bprint.c debug.c
    memory.c options.c sockbuf.c
    ${PLAT_SRCS}
)

set(OBJS
    assert.lo decode.lo encode.lo io.lo bprint.lo debug.lo
    memory.lo options.lo sockbuf.lo
    #${@PLAT@_OBJS}
)

set(XSRCS version.c)

set(PROGRAMS )#dtest etest idtest)

# Include directories
set(LDAP_INCDIR ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set(LDAP_LIBDIR ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

# Libraries
set(XLIBS ${LIBRARY} ${LDAP_LIBLUTIL_A})
set(XXLIBS)

# Define the target library
add_library(lber STATIC ${SRCS})

# Link libraries
target_link_libraries(lber ${XLIBS} ${XXLIBS})

# Include directories
target_include_directories(lber PRIVATE ${LDAP_INCDIR})

add_dependencies(lber configure_ldap)

# Link directories
target_link_directories(lber PRIVATE ${LDAP_LIBDIR})

set(LIBRARY_OUTPUT_DIRECTORY    ${PROJECT_BINARY_DIR}/${M4S_LIBRARY_OUTPUT_DIRECTORY})
set(ARCHIVE_OUTPUT_DIRECTORY    ${PROJECT_BINARY_DIR}/${M4S_ARCHIVE_OUTPUT_DIRECTORY})
set(RUNTIME_OUTPUT_DIRECTORY    ${PROJECT_BINARY_DIR}/${M4S_RUNTIME_OUTPUT_DIRECTORY})
set(EXECUTABLE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/${M4S_RUNTIME_OUTPUT_DIRECTORY})

# Install the target
install(TARGETS lber
  RUNTIME DESTINATION ${M4S_RUNTIME_OUTPUT_DIRECTORY}
  LIBRARY DESTINATION ${M4S_LIBRARY_OUTPUT_DIRECTORY}
  ARCHIVE DESTINATION ${M4S_ARCHIVE_OUTPUT_DIRECTORY})

