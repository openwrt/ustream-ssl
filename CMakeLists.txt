cmake_minimum_required(VERSION 2.6)

INCLUDE(CheckSymbolExists)

PROJECT(ustream-ssl C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(MBEDTLS)
  ADD_DEFINITIONS(-DHAVE_MBEDTLS)
  SET(SSL_SRC ustream-mbedtls.c)
  SET(SSL_LIB mbedtls mbedcrypto mbedx509 m)
ELSEIF(WOLFSSL)
  ADD_DEFINITIONS(-DHAVE_WOLFSSL)
  SET(SSL_SRC ustream-io-wolfssl.c ustream-openssl.c)
  SET(SSL_LIB wolfssl m)
  SET(CMAKE_REQUIRED_LIBRARIES "-lwolfssl -lm")
  CHECK_SYMBOL_EXISTS (wolfSSL_SSLSetIORecv "wolfssl/ssl.h"
		       HAVE_WOLFSSL_SSLSETIORECV)
  IF (NOT HAVE_WOLFSSL_SSLSETIORECV)
    ADD_DEFINITIONS(-DNO_WOLFSSL_SSLSETIO_SEND_RECV)
  ENDIF()
ELSE()
  SET(SSL_SRC ustream-io-openssl.c ustream-openssl.c)
  SET(SSL_LIB crypto ssl)
ENDIF()

FIND_PATH(ubox_include_dir libubox/ustream.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

ADD_LIBRARY(ustream-ssl SHARED ustream-ssl.c ${SSL_SRC})
TARGET_LINK_LIBRARIES(ustream-ssl ubox ${SSL_LIB})

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
