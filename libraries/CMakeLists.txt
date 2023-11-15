cmake_minimum_required(VERSION 3.10)

project(Libraries)

# List of subdirectories
set(SUBDIRS
    #liblutil
    liblber
    #liblunicode
    libldap
    #librewrite
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

# Install pkg-config files
set(PKGCONFIG_DEST_DIR ${CMAKE_INSTALL_PREFIX}/lib/pkgconfig)
foreach(subdir ${SUBDIRS})
    #file(GLOB PKGCONFIG_FILES "${CMAKE_CURRENT_SOURCE_DIR}/${subdir}/*.pc")
    #install(FILES ${PKGCONFIG_FILES} DESTINATION ${PKGCONFIG_DEST_DIR})
    add_subdirectory(${subdir})
endforeach()
