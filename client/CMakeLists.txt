set(shared_src client_shared.c client_shared.h client_props.c)

if (WITH_SRV)
	add_definitions("-DWITH_SRV")
endif (WITH_SRV)

set( CLIENT_INC ${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
            ${STDBOOL_H_PATH} ${STDINT_H_PATH} ${PTHREAD_INCLUDE_DIR}
            ${OPENSSL_INCLUDE_DIR})

set( CLIENT_DIR ${mosquitto_BINARY_DIR}/lib)

if (CJSON_FOUND)
	add_definitions("-DWITH_CJSON")
	set( CLIENT_DIR "${CLIENT_DIR};${CJSON_DIR}" )
	set( CLIENT_INC "${CLIENT_INC};${CJSON_INCLUDE_DIRS}" )
endif()

include_directories(${CLIENT_INC})
link_directories(${CLIENT_DIR})

add_executable(mosquitto_pub pub_client.c pub_shared.c ${shared_src})
add_executable(wtrobot sub_client.c sub_client_output.c sqlite3.c ${shared_src})

if (CJSON_FOUND)
	target_link_libraries(mosquitto_pub ${CJSON_LIBRARIES})
	target_link_libraries(wtrobot ${CJSON_LIBRARIES})
endif()

if (WITH_STATIC_LIBRARIES)
	target_link_libraries(mosquitto_pub libmosquitto_static)
	target_link_libraries(wtrobot libmosquitto_static pthread dl)
endif()

if (QNX)
    target_link_libraries(mosquitto_pub socket)
    target_link_libraries(wtrobot socket)
endif()

install(TARGETS mosquitto_pub RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS wtrobot RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
