set(MB_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(MB_PORT ${MB_ROOT}/port)

set(JASPER_ROOT ${MB_ROOT}/vendor/codecs/jasper-1.701.0/src/libjasper)
file(GLOB JASPER_PRIVATE_SOURCES
  ${JASPER_ROOT}/base/*.c
  ${JASPER_ROOT}/mif/*.c
  ${JASPER_ROOT}/pnm/*.c
  ${JASPER_ROOT}/jp2/*.c
  ${JASPER_ROOT}/jpc/*.c)
add_library(group-pmp-mediabench-jp2 STATIC
  ${JASPER_PRIVATE_SOURCES} ${MB_PORT}/jp2-memory.c)
target_include_directories(group-pmp-mediabench-jp2 PUBLIC
  ${MB_PORT} ${JASPER_ROOT}/include)
target_compile_definitions(group-pmp-mediabench-jp2 PRIVATE
  GROUP_PMP_ENCLAVE_PRIVATE_CODEC=1
  EXCLUDE_BMP_SUPPORT=1 EXCLUDE_RAS_SUPPORT=1
  EXCLUDE_JPG_SUPPORT=1 EXCLUDE_PGX_SUPPORT=1)
target_compile_options(group-pmp-mediabench-jp2 PRIVATE -O2 -w)

set(JM_ROOT ${MB_ROOT}/vendor/codecs/JM)
foreach(kind enc dec)
  if(kind STREQUAL "enc")
    set(jm_dir lencod)
    set(jm_main group_pmp_jm_encoder_main)
  else()
    set(jm_dir ldecod)
    set(jm_main group_pmp_jm_decoder_main)
  endif()
  file(GLOB jm_sources ${JM_ROOT}/${jm_dir}/src/*.c)
  set_source_files_properties(${JM_ROOT}/${jm_dir}/src/${jm_dir}.c
    PROPERTIES COMPILE_DEFINITIONS "main=${jm_main}")
  add_library(group-pmp-mediabench-h264-${kind} STATIC
    ${jm_sources} ${MB_PORT}/h264-memory.c ${MB_PORT}/jm-memory-vfs.c)
  target_include_directories(group-pmp-mediabench-h264-${kind} PUBLIC
    ${MB_PORT} ${JM_ROOT}/${jm_dir}/inc)
  target_compile_options(group-pmp-mediabench-h264-${kind} PRIVATE
    -O2 -fcommon -w)
  target_compile_definitions(group-pmp-mediabench-h264-${kind} PRIVATE
    _FILE_OFFSET_BITS=64)
  set_source_files_properties(${jm_sources} PROPERTIES
    COMPILE_FLAGS "-include ${MB_PORT}/jm-memory-redirect.h")
  if(kind STREQUAL "enc")
    target_compile_definitions(group-pmp-mediabench-h264-${kind} PRIVATE
      GROUP_PMP_H264_ENCODER=1)
  endif()
endforeach()

set(FFMPEG_ROOT ${CMAKE_CURRENT_BINARY_DIR}/ffmpeg-private)
file(MAKE_DIRECTORY ${FFMPEG_ROOT})
string(REGEX REPLACE "gcc$" "" FFMPEG_CROSS_PREFIX "${CMAKE_C_COMPILER}")
if("${FFMPEG_CROSS_PREFIX}" STREQUAL "${CMAKE_C_COMPILER}")
  set(FFMPEG_CROSS_PREFIX "")
endif()
add_custom_command(
  OUTPUT ${FFMPEG_ROOT}/libavcodec/libavcodec.a
         ${FFMPEG_ROOT}/libavutil/libavutil.a
  COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${MB_ROOT}/vendor/codecs/ffmpeg ${FFMPEG_ROOT}
  COMMAND sh configure
    --cross-prefix=${FFMPEG_CROSS_PREFIX}
    --cpu=unknown --disable-mmx --disable-strip --disable-network
    --disable-encoders --disable-decoders
    --enable-encoder=mpeg4 --enable-decoder=mpeg4
    --disable-vhook --extra-cflags=-fgnu89-inline
  COMMAND make -C libavutil
  COMMAND make -C libavcodec
  WORKING_DIRECTORY ${FFMPEG_ROOT}
  VERBATIM)
add_custom_target(group-pmp-mediabench-ffmpeg-build DEPENDS
  ${FFMPEG_ROOT}/libavcodec/libavcodec.a
  ${FFMPEG_ROOT}/libavutil/libavutil.a)
add_library(group-pmp-mediabench-mpeg4 STATIC ${MB_PORT}/mpeg4-memory.c)
target_include_directories(group-pmp-mediabench-mpeg4 PUBLIC
  ${MB_PORT} ${FFMPEG_ROOT} ${FFMPEG_ROOT}/libavutil)
add_dependencies(group-pmp-mediabench-mpeg4
  group-pmp-mediabench-ffmpeg-build)
target_compile_options(group-pmp-mediabench-mpeg4 PRIVATE -O2)

add_library(group-pmp-mediabench-media-io STATIC ${MB_PORT}/media-io.c)
target_include_directories(group-pmp-mediabench-media-io PUBLIC
  ${MB_PORT} ${CMAKE_CURRENT_SOURCE_DIR}/../eapp)
add_library(group-pmp-mediabench-host-io STATIC ${MB_PORT}/media-store.c)
target_include_directories(group-pmp-mediabench-host-io PUBLIC ${MB_PORT})
add_library(group-pmp-mediabench-board-common STATIC
  ${MB_PORT}/media-board-files.c ${MB_PORT}/media-source.c)
target_include_directories(group-pmp-mediabench-board-common PUBLIC ${MB_PORT})
