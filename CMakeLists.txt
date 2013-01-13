cmake_minimum_required(VERSION 2.6)

PROJECT(ustream-ssl C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()

IF (CYASSL)
  SET(SSL_LIB cyassl)
ELSE()
  SET(SSL_LIB crypto ssl)
ENDIF()

ADD_LIBRARY(ustream-ssl SHARED ustream-ssl.c ustream-io.c)
TARGET_LINK_LIBRARIES(ustream-ssl ubox ${SSL_LIB})

ADD_EXECUTABLE(ustream-example ustream-example.c)
TARGET_LINK_LIBRARIES(ustream-example ustream-ssl)

SET(CMAKE_INSTALL_PREFIX /usr)

FILE(GLOB headers *.h)
INSTALL(FILES ${headers}
	DESTINATION include/libubox
)
INSTALL(TARGETS ustream-ssl
	LIBRARY DESTINATION lib
)
