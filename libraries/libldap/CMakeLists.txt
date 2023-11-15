# CMakeLists.txt for LDAP -lldap in OpenLDAP
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

project(LDAP LANGUAGES C)

# List of source files
set(SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/ldap_config.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/portable.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/ldap_features.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/lber_types.h
    bind.c open.c result.c error.c compare.c search.c
    controls.c messages.c references.c extended.c cyrus.c
    modify.c add.c modrdn.c delete.c abandon.c
    sasl.c sbind.c unbind.c cancel.c
    filter.c free.c sort.c passwd.c whoami.c vc.c
    getdn.c getentry.c getattr.c getvalues.c addentry.c
    request.c os-ip.c url.c pagectrl.c sortctrl.c vlvctrl.c
    init.c options.c print.c string.c util-int.c schema.c
    charray.c os-local.c dnssrv.c utf-8.c utf-8-conv.c
    tls2.c tls_o.c tls_g.c
    turn.c ppolicy.c dds.c txn.c ldap_sync.c stctrl.c
    assertion.c deref.c ldifutil.c ldif.c fetch.c lbase64.c
    msctrl.c psearchctrl.c threads.c rdwr.c tpool.c rq.c
    thr_posix.c thr_thr.c thr_nt.c thr_pth.c thr_debug.c
    account_usability.c avl.c tavl.c testavl.c
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)


# Set the object file extension
set(O "lo")

# Create object files from source files
foreach(src ${SRCS})
    get_filename_component(base ${src} NAME_WE)
    list(APPEND OBJS ${base}.${O})
endforeach()

# Include directories
set(LDAP_INCDIR ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
set(LDAP_LIBDIR ${CMAKE_CURRENT_SOURCE_DIR}/../../libraries)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

# Libraries
set(XLIBS ${LIBRARY} ${LDAP_LIBLBER_LA} ${LDAP_LIBLUTIL_A})
set(XXLIBS ${SECURITY_LIBS} ${LUTIL_LIBS})

# Define the target library
add_library(ldap STATIC ${SRCS})

# Add a custom command to run the "configure" script before building
add_custom_target(configure_ldap
    #COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/../../configure
    #WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../
)

# Include directories
target_include_directories(ldap PUBLIC ${LDAP_INCDIR})

# Set the "configure_ldap" target as a dependency for the "ldap" target
add_dependencies(ldap configure_ldap)

set(LIBRARY_OUTPUT_DIRECTORY    ${PROJECT_BINARY_DIR}/${M4S_LIBRARY_OUTPUT_DIRECTORY})
set(ARCHIVE_OUTPUT_DIRECTORY    ${PROJECT_BINARY_DIR}/${M4S_ARCHIVE_OUTPUT_DIRECTORY})
set(RUNTIME_OUTPUT_DIRECTORY    ${PROJECT_BINARY_DIR}/${M4S_RUNTIME_OUTPUT_DIRECTORY})
set(EXECUTABLE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/${M4S_RUNTIME_OUTPUT_DIRECTORY})

# Install the target
install(TARGETS ldap
  RUNTIME DESTINATION ${M4S_RUNTIME_OUTPUT_DIRECTORY}
  LIBRARY DESTINATION ${M4S_LIBRARY_OUTPUT_DIRECTORY}
  ARCHIVE DESTINATION ${M4S_ARCHIVE_OUTPUT_DIRECTORY})

if(NOT WIN32)
	set(NIX_LIBS)
endif()

# Link libraries
target_link_libraries(ldap 
	${XLIBS} ${XXLIBS}
	${NIX_LIBS}
)

# Link directories
target_link_directories(ldap PRIVATE ${LDAP_LIBDIR})
