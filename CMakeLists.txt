# CMakeLists.txt for OpenLDAP
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

project(OpenLDAP VERSION 2.5.16 LANGUAGES C)

include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(${CMAKE_CURRENT_SOURCE_DIR}/config.cmake)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_subdirectory(include)
add_subdirectory(libraries)
#add_subdirectory(clients)
#add_subdirectory(servers)
#add_subdirectory(tests)
#add_subdirectory(doc)

#execute_process(COMMAND sh ${CMAKE_SOURCE_DIR}/configure)
