cmake_minimum_required(VERSION 3.10)

project(OpenLDAPConfig)

# Configuration for OpenLDAP
configure_file(ldap_config.hin ${CMAKE_CURRENT_SOURCE_DIR}/ldap_config.h)
configure_file(portable.hin ${CMAKE_CURRENT_SOURCE_DIR}/portable.h)
configure_file(ldap_features.hin ${CMAKE_CURRENT_SOURCE_DIR}/ldap_features.h)
configure_file(lber_types.hin ${CMAKE_CURRENT_SOURCE_DIR}/lber_types.h)

# List of header files to be installed
#set(HEADERS
#    ${CMAKE_CURRENT_SOURCE_DIR}/ldap_config.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/lber.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/lber_types.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/ldap.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/ldap_cdefs.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/ldap_schema.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/ldap_utf8.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/slapi-plugin.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/ldap_features.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/ldif.h
#    ${CMAKE_CURRENT_SOURCE_DIR}/openldap.h
#)

#foreach(_f ${HEADERS})
#    file(COPY ${_f} DESTINATION $CMAKE_SOURCE_DIR/include)
#endforeach()

# Install headers
#install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
