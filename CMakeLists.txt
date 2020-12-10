cmake_minimum_required(VERSION 2.6)

PROJECT(ustream-ssl C)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3)
IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
        ADD_DEFINITIONS(-Wextra -Werror=implicit-function-declaration)
        ADD_DEFINITIONS(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
ADD_DEFINITIONS(-Wno-unused-parameter -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(MBEDTLS)
  ADD_DEFINITIONS(-DHAVE_MBEDTLS)
  SET(SSL_SRC ustream-mbedtls.c)
  FIND_LIBRARY(mbedtls_library mbedtls)
  FIND_LIBRARY(mbedx509_library mbedx509)
  FIND_LIBRARY(mbedcrypto_library mbedcrypto)
  SET(SSL_LIB ${mbedtls_library} ${mbedx509_library} ${mbedcrypto_library} m)
ELSEIF(WOLFSSL)
  ADD_DEFINITIONS(-DHAVE_WOLFSSL)
  FIND_LIBRARY(wolfssl_library wolfssl)
  SET(SSL_SRC ustream-io-wolfssl.c ustream-openssl.c)
  SET(SSL_LIB ${wolfssl_library} m)
  SET(CMAKE_REQUIRED_LIBRARIES "${wolfssl_library} -lm")
ELSE()
  SET(SSL_SRC ustream-io-openssl.c ustream-openssl.c)
  SET(SSL_LIB crypto ssl)
ENDIF()

FIND_PATH(ubox_include_dir libubox/ustream.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})
FIND_LIBRARY(ubox_library NAMES ubox)

ADD_LIBRARY(ustream-ssl SHARED ustream-ssl.c ${SSL_SRC})
TARGET_LINK_LIBRARIES(ustream-ssl ${ubox_library} ${SSL_LIB})

ADD_EXECUTABLE(ustream-example-server ustream-example-server.c)
TARGET_LINK_LIBRARIES(ustream-example-server ustream-ssl)

ADD_EXECUTABLE(ustream-example-client ustream-example-client.c)
TARGET_LINK_LIBRARIES(ustream-example-client ustream-ssl)

INSTALL(FILES ustream-ssl.h
	DESTINATION include/libubox
)
INSTALL(TARGETS ustream-ssl
	LIBRARY DESTINATION lib
)
