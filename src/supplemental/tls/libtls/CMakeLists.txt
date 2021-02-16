#
# Copyright 2021 Dave Voutila <dave@sisu.io>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

if (NNG_TLS_ENGINE STREQUAL "libtls")
  nng_sources(tls.c)
  nng_defines(NNG_TLS_ENGINE_INIT=nng_tls_engine_init_libtls)
  nng_defines(NNG_TLS_ENGINE_FINI=nng_tls_engine_fini_libtls)
  nng_defines(NNG_SUPP_TLS)

  nng_defines(NNG_USING_LIBTLS)

  #TODO: portable logic for finding libtls
  find_library(LIBTLS_LIB "tls")
  message("found tls at: ${LIBTLS_LIB}")
  nng_link_libraries(${LIBTLS_LIB})
endif()
