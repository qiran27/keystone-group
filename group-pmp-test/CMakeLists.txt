cmake_minimum_required(VERSION 3.10)
project(group-pmp-test C CXX)

set(GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT 256 CACHE STRING
  "Common Async/Adaptive descriptors per UTM buffer: 256 baseline, 488 experiment")
if(NOT GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT MATCHES "^(256|488)$")
  message(FATAL_ERROR "GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT must be 256 or 488")
endif()
add_definitions(-DGROUP_PMP_SQLITE_DESCRIPTOR_LIMIT=${GROUP_PMP_SQLITE_DESCRIPTOR_LIMIT})

option(GROUP_PMP_ENABLE_SPARK_SCHEDULER
  "Build the retired Spark-style P11 task scheduler experiment" OFF)
if(GROUP_PMP_ENABLE_SPARK_SCHEDULER)
  add_definitions(-DGROUP_PMP_ENABLE_SPARK_SCHEDULER=1)
else()
  add_definitions(-DGROUP_PMP_ENABLE_SPARK_SCHEDULER=0)
endif()

option(GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS
  "Build retired pure-AES enclave perf/scale benchmarks" OFF)
if(GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS)
  add_definitions(-DGROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS=1)
else()
  add_definitions(-DGROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS=0)
endif()

option(GROUP_PMP_ENABLE_NATIVE_AES_DIAGNOSTIC
  "Build native AES and multi-algorithm crypto diagnostics" ON)

set(KEYSTONE_SDK_SRC_DIR "" CACHE PATH
  "Keystone source SDK path for current host and eapp SDK objects")

option(GROUP_PMP_AES_COOPERATIVE_SERVICE
  "Enable legacy 256 KiB AES release/yield/reacquire service points" OFF)
if(GROUP_PMP_AES_COOPERATIVE_SERVICE)
  add_definitions(-DGROUP_PMP_AES_COOPERATIVE_SERVICE=1)
else()
  add_definitions(-DGROUP_PMP_AES_COOPERATIVE_SERVICE=0)
endif()

set(GROUP_PMP_TASK_BATCHES 100 CACHE STRING
  "P11/P15 hardware task batches executed by each worker lane")
if(NOT GROUP_PMP_TASK_BATCHES MATCHES "^[0-9]+$" OR
   GROUP_PMP_TASK_BATCHES LESS 1 OR GROUP_PMP_TASK_BATCHES GREATER 100)
  message(FATAL_ERROR "GROUP_PMP_TASK_BATCHES must be in [1, 100]")
endif()

set(GROUP_PMP_AES_MARCH "rv64gc" CACHE STRING
  "RISC-V ISA used by both native and enclave AES baseline targets")
set(GROUP_PMP_AES_MABI "lp64d" CACHE STRING
  "RISC-V ABI used by both native and enclave AES baseline targets")
set(GROUP_PMP_AES_COMPILE_OPTIONS
  -O3
  -march=${GROUP_PMP_AES_MARCH}
  -mabi=${GROUP_PMP_AES_MABI})

function(configure_group_pmp_aes_target target)
  target_compile_options(${target} PRIVATE ${GROUP_PMP_AES_COMPILE_OPTIONS})
  target_compile_definitions(${target} PRIVATE
    AES_FULL_UNROLL=1
    GROUP_PMP_AES_MARCH_STRING="${GROUP_PMP_AES_MARCH}"
    GROUP_PMP_AES_MABI_STRING="${GROUP_PMP_AES_MABI}"
    GROUP_PMP_AES_OPT_LEVEL=3)
endfunction()

set(eyrie_plugins "io_syscall linux_syscall env_setup")

set(GROUP_PMP_EAPP_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}/eapp
  ${KEYSTONE_SDK_DIR}/include/app
  ${KEYSTONE_SDK_DIR}/include/edge)

function(add_group_pmp_eapp target source output_name)
  add_executable(${target} ${source})
  target_include_directories(${target} PRIVATE ${GROUP_PMP_EAPP_INCLUDE_DIRS})
  target_link_libraries(${target}
    ${KEYSTONE_LIB_EAPP}
    ${KEYSTONE_LIB_EDGE}
    "-static")
  # Keystone's tiny allocator grows from the end of the loaded eapp image.
  set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS
    " -Wl,--defsym=__malloc_start=_end")
  set_target_properties(${target} PROPERTIES
    OUTPUT_NAME "${output_name}"
    SUFFIX ".eapp_riscv")
endfunction()

function(add_group_pmp_eapp_sources target output_name)
  add_executable(${target} ${ARGN})
  target_include_directories(${target} PRIVATE ${GROUP_PMP_EAPP_INCLUDE_DIRS})
  target_link_libraries(${target}
    ${KEYSTONE_LIB_EAPP}
    ${KEYSTONE_LIB_EDGE}
    "-static")
  set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS
    " -Wl,--defsym=__malloc_start=_end")
  set_target_properties(${target} PROPERTIES
    OUTPUT_NAME "${output_name}"
    SUFFIX ".eapp_riscv")
endfunction()

# Shared AEAD primitives; the standalone fixture remains a separate executable.
set(SECURITY_MBEDTLS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/security/vendor/mbedtls-3.6.7)
set(SECURITY_MBEDTLS_SOURCES)
foreach(unit aes gcm block_cipher chacha20 poly1305 chachapoly platform_util constant_time)
  list(APPEND SECURITY_MBEDTLS_SOURCES ${SECURITY_MBEDTLS_ROOT}/library/${unit}.c)
endforeach()
add_library(group-pmp-security-aead-lib STATIC
  security/security-aead.c eapp/benchmark-cipher.c ${SECURITY_MBEDTLS_SOURCES})
target_include_directories(group-pmp-security-aead-lib PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/security ${SECURITY_MBEDTLS_ROOT}/include
  ${SECURITY_MBEDTLS_ROOT}/library)
target_compile_definitions(group-pmp-security-aead-lib PRIVATE
  MBEDTLS_CONFIG_FILE="aead-config.h")
target_compile_options(group-pmp-security-aead-lib PRIVATE ${GROUP_PMP_AES_COMPILE_OPTIONS})
add_group_pmp_eapp(group-pmp-security-aead eapp/group-pmp-security-aead.c
  group-pmp-security-aead)
target_link_libraries(group-pmp-security-aead group-pmp-security-aead-lib
  ${KEYSTONE_LIB_EAPP})

add_group_pmp_eapp_sources(group-pmp-crypto-compute-worker group-pmp-crypto-compute-worker
  eapp/group-pmp-crypto-compute-worker.c eapp/crypto-compute.c
  eapp/group-pmp-crypto.c eapp/aes_core.c)
configure_group_pmp_aes_target(group-pmp-crypto-compute-worker)
target_link_libraries(group-pmp-crypto-compute-worker group-pmp-security-aead-lib
  ${KEYSTONE_LIB_EAPP})

add_group_pmp_eapp_sources(group-pmp-motivation-worker group-pmp-motivation-worker
  eapp/group-pmp-motivation-worker.c motivation/core.c motivation/architecture.c eapp/aes_core.c)
target_include_directories(group-pmp-motivation-worker PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/security ${SECURITY_MBEDTLS_ROOT}/include)
target_compile_definitions(group-pmp-motivation-worker PRIVATE
  MBEDTLS_CONFIG_FILE="aead-config.h")
configure_group_pmp_aes_target(group-pmp-motivation-worker)
target_link_libraries(group-pmp-motivation-worker group-pmp-security-aead-lib
  ${KEYSTONE_LIB_EAPP})

set(GROUP_PMP_SECURITY_ACCESS_TARGETS)
foreach(kind epm tsr-unacquired tsr-cross tsr-revoked)
  if(kind STREQUAL "epm")
    set(region 1)
  elseif(kind STREQUAL "tsr-unacquired")
    set(region 2)
  elseif(kind STREQUAL "tsr-cross")
    set(region 3)
  else()
    set(region 4)
  endif()
  foreach(operation read write)
    set(target group-pmp-security-${kind}-${operation})
    add_group_pmp_eapp(${target} eapp/group-pmp-security-access.c ${target})
    if(operation STREQUAL "write")
      set(write_access 1)
    else()
      set(write_access 0)
    endif()
    target_compile_definitions(${target} PRIVATE SECURITY_TARGET=${region} SECURITY_WRITE=${write_access})
    list(APPEND GROUP_PMP_SECURITY_ACCESS_TARGETS ${target})
  endforeach()
endforeach()
add_executable(group-pmp-security-scan security/security-scan.cpp)
set_target_properties(group-pmp-security-scan PROPERTIES
  CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_link_libraries(group-pmp-security-scan pthread)
add_executable(group-pmp-security-capture security/security-capture.cpp)
set_target_properties(group-pmp-security-capture PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_link_libraries(group-pmp-security-capture pthread)

add_group_pmp_eapp(
  group-pmp-private-probe
  eapp/group-pmp-private-probe.c
  group-pmp-private-probe)
add_group_pmp_eapp(
  group-pmp-timeslice-a
  eapp/group-pmp-timeslice-a.c
  group-pmp-timeslice-a)
add_group_pmp_eapp(
  group-pmp-timeslice-b
  eapp/group-pmp-timeslice-b.c
  group-pmp-timeslice-b)
add_group_pmp_eapp(
  group-pmp-timeslice-check
  eapp/group-pmp-timeslice-check.c
  group-pmp-timeslice-check)
add_group_pmp_eapp(
  group-pmp-lease-hold
  eapp/group-pmp-lease-hold.c
  group-pmp-lease-hold)
add_group_pmp_eapp(
  group-pmp-ocall-blocker
  eapp/group-pmp-ocall-blocker.c
  group-pmp-ocall-blocker)
add_group_pmp_eapp(
  group-pmp-mw-master-dispatch
  eapp/group-pmp-mw-master-dispatch.c
  group-pmp-mw-master-dispatch)
add_group_pmp_eapp(
  group-pmp-mw-worker
  eapp/group-pmp-mw-worker.c
  group-pmp-mw-worker)
add_group_pmp_eapp(
  group-pmp-mw-master-aggregate
  eapp/group-pmp-mw-master-aggregate.c
  group-pmp-mw-master-aggregate)
add_group_pmp_eapp(
  group-pmp-mw-master-miss
  eapp/group-pmp-mw-master-miss.c
  group-pmp-mw-master-miss)
add_group_pmp_eapp(
  group-pmp-mw-worker-dispatch-rw-denied
  eapp/group-pmp-mw-worker-dispatch-rw-denied.c
  group-pmp-mw-worker-dispatch-rw-denied)
add_group_pmp_eapp(
  group-pmp-mw-worker-cross-slice-fault
  eapp/group-pmp-mw-worker-cross-slice-fault.c
  group-pmp-mw-worker-cross-slice-fault)
add_group_pmp_eapp(
  group-pmp-mw-worker-slice0-fault
  eapp/group-pmp-mw-worker-slice0-fault.c
  group-pmp-mw-worker-slice0-fault)
add_group_pmp_eapp(
  group-pmp-mw-master-aggregate-rw-denied
  eapp/group-pmp-mw-master-aggregate-rw-denied.c
  group-pmp-mw-master-aggregate-rw-denied)
add_group_pmp_eapp(
  group-pmp-mw-no-acquire-fault
  eapp/group-pmp-mw-no-acquire-fault.c
  group-pmp-mw-no-acquire-fault)
add_group_pmp_eapp(
  group-pmp-mw-release-fault
  eapp/group-pmp-mw-release-fault.c
  group-pmp-mw-release-fault)
add_group_pmp_eapp(
  group-pmp-mw-hold-yield
  eapp/group-pmp-mw-hold-yield.c
  group-pmp-mw-hold-yield)
add_group_pmp_eapp(
  group-pmp-mw-inherit-fault
  eapp/group-pmp-mw-inherit-fault.c
  group-pmp-mw-inherit-fault)
add_group_pmp_eapp(
  group-pmp-mw-exec-fault
  eapp/group-pmp-mw-exec-fault.c
  group-pmp-mw-exec-fault)
add_group_pmp_eapp(
  group-pmp-mw-master-fault
  eapp/group-pmp-mw-master-fault.c
  group-pmp-mw-master-fault)
add_group_pmp_eapp_sources(
  group-pmp-mixed-master
  group-pmp-mixed-master
  eapp/group-pmp-mixed-master.c
  eapp/aes_core.c)
configure_group_pmp_aes_target(group-pmp-mixed-master)
add_group_pmp_eapp_sources(
  group-pmp-mixed-worker
  group-pmp-mixed-worker
  eapp/group-pmp-mixed-worker.c
  eapp/aes_core.c)
configure_group_pmp_aes_target(group-pmp-mixed-worker)
add_group_pmp_eapp(
  group-pmp-sqlite-master
  eapp/group-pmp-sqlite-master.c
  group-pmp-sqlite-master)
target_compile_options(group-pmp-sqlite-master PRIVATE -O3)
add_group_pmp_eapp_sources(
  group-pmp-sqlite-worker
  group-pmp-sqlite-worker
  eapp/group-pmp-sqlite-worker.c
  eapp/aes_core.c
  eapp/group-pmp-crypto.c
  sqlite-bench-master/keystone_enclave_store.c)
target_include_directories(group-pmp-sqlite-worker BEFORE PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/sqlite-bench-master)
target_compile_options(group-pmp-sqlite-worker PRIVATE
  -O3
  -fno-stack-protector
  -Wno-builtin-declaration-mismatch
  -Wno-missing-field-initializers
  -Wno-unused-function
  -Wno-unused-variable
  -Wno-unused-parameter
  -Wno-sign-compare
  -Wno-maybe-uninitialized
  -Wno-cast-function-type
  -Wno-misleading-indentation
  -Wno-return-local-addr)
configure_group_pmp_aes_target(group-pmp-sqlite-worker)
target_link_libraries(group-pmp-sqlite-worker group-pmp-security-aead-lib ${KEYSTONE_LIB_EAPP})

# Independent KV payload adapter; shared transport/AES policy is unchanged.
add_group_pmp_eapp_sources(group-pmp-kv-worker group-pmp-kv-worker
  eapp/group-pmp-sqlite-worker.c eapp/aes_core.c eapp/group-pmp-crypto.c
  sqlite-bench-master/keystone_enclave_store.c secure-kv/kv-record.c)
target_include_directories(group-pmp-kv-worker BEFORE PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/sqlite-bench-master)
target_compile_definitions(group-pmp-kv-worker PRIVATE GROUP_PMP_KV_WORKER=1)
configure_group_pmp_aes_target(group-pmp-kv-worker)
target_link_libraries(group-pmp-kv-worker group-pmp-security-aead-lib ${KEYSTONE_LIB_EAPP})

# Separate workers keep the production SQLite worker and its AES unchanged.
set_source_files_properties(
  rv8-bench-master/src/aes.c rv8-bench-master/src/miniz.c
  rv8-bench-master/src/norx.c rv8-bench-master/src/qsort.c
  rv8-bench-master/src/sha512.c rv8-bench-master/src/bigint.cc
  rv8-bench-master/src/dhrystone.c rv8-bench-master/src/primes.c
  PROPERTIES COMPILE_FLAGS "-w")
set(GROUP_PMP_RV8_TARGETS)
set(rv8_profile 0)
foreach(kernel bigint miniz norx aes qsort sha-512 dhrystone primes)
  math(EXPR rv8_profile "${rv8_profile} + 1")
  set(target group-pmp-rv8-${kernel}-worker)
  add_group_pmp_eapp_sources(${target} ${target}
    eapp/group-pmp-rv8-worker.c
    rv8-bench-master/port/rv8-kernels.c
    rv8-bench-master/src/aes.c rv8-bench-master/src/miniz.c
    rv8-bench-master/src/norx.c rv8-bench-master/src/qsort.c
    rv8-bench-master/src/sha512.c
    rv8-bench-master/src/dhrystone.c rv8-bench-master/src/primes.c)
  if(kernel STREQUAL "bigint")
    target_sources(${target} PRIVATE rv8-bench-master/src/bigint.cc)
    target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>)
    set_property(TARGET ${target} PROPERTY CXX_STANDARD 11)
  endif()
  target_include_directories(${target} BEFORE PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sqlite-bench-master
    ${CMAKE_CURRENT_SOURCE_DIR}/rv8-bench-master/port)
  target_compile_definitions(${target} PRIVATE
    RV8_BENCH_LIBRARY=1 RV8_PROFILE=${rv8_profile})
  configure_group_pmp_aes_target(${target})
  list(APPEND GROUP_PMP_RV8_TARGETS ${target})
endforeach()

set(GROUP_PMP_JPEG6B_ROOT
  ${CMAKE_CURRENT_SOURCE_DIR}/mediabench-ii/vendor/codecs/jpeg-6b)
set(GROUP_PMP_JPEG6B_SOURCES
  jcapimin.c jcapistd.c jccoefct.c jccolor.c jcdctmgr.c jchuff.c
  jcinit.c jcmainct.c jcmarker.c jcmaster.c jcomapi.c jcparam.c
  jcphuff.c jcprepct.c jcsample.c jctrans.c jdapimin.c jdapistd.c
  jdatadst.c jdatasrc.c jdcoefct.c jdcolor.c jddctmgr.c jdhuff.c
  jdinput.c jdmainct.c jdmarker.c jdmaster.c jdmerge.c jdphuff.c
  jdpostct.c jdsample.c jdtrans.c jerror.c jfdctflt.c jfdctfst.c
  jfdctint.c jidctflt.c jidctfst.c jidctint.c jidctred.c jquant1.c
  jquant2.c jutils.c jmemmgr.c jmemnobs.c)
set(GROUP_PMP_JPEG6B_FILES)
foreach(source ${GROUP_PMP_JPEG6B_SOURCES})
  list(APPEND GROUP_PMP_JPEG6B_FILES ${GROUP_PMP_JPEG6B_ROOT}/${source})
endforeach()
add_library(group-pmp-mediabench-jpeg STATIC
  ${GROUP_PMP_JPEG6B_FILES}
  mediabench-ii/port/jpeg-memory.c)
target_include_directories(group-pmp-mediabench-jpeg PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/mediabench-ii/port
  ${GROUP_PMP_JPEG6B_ROOT})
target_compile_options(group-pmp-mediabench-jpeg PRIVATE -O3)
set_source_files_properties(${GROUP_PMP_JPEG6B_FILES} PROPERTIES
  COMPILE_FLAGS "-w")

add_subdirectory(mediabench-ii)

foreach(codec mpeg4 jp2 h264-enc h264-dec)
  add_group_pmp_eapp_sources(
    group-pmp-mediabench-${codec}-linkcheck
    group-pmp-mediabench-${codec}-linkcheck
    eapp/group-pmp-mediabench-linkcheck.c)
  target_include_directories(group-pmp-mediabench-${codec}-linkcheck PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mediabench-ii/port)
  target_link_libraries(group-pmp-mediabench-${codec}-linkcheck
    group-pmp-mediabench-${codec} m)
endforeach()
target_compile_definitions(group-pmp-mediabench-mpeg4-linkcheck PRIVATE
  GROUP_PMP_MEDIABENCH_LINK_MPEG4=1)
target_link_libraries(group-pmp-mediabench-mpeg4-linkcheck
  ${CMAKE_CURRENT_BINARY_DIR}/mediabench-ii/ffmpeg-private/libavcodec/libavcodec.a
  ${CMAKE_CURRENT_BINARY_DIR}/mediabench-ii/ffmpeg-private/libavutil/libavutil.a
  m)
add_dependencies(group-pmp-mediabench-mpeg4-linkcheck
  group-pmp-mediabench-ffmpeg-build)
target_compile_definitions(group-pmp-mediabench-jp2-linkcheck PRIVATE
  GROUP_PMP_MEDIABENCH_LINK_JP2=1)
add_group_pmp_eapp_sources(
  group-pmp-mediabench-io-linkcheck
  group-pmp-mediabench-io-linkcheck
  eapp/group-pmp-mediabench-linkcheck.c
  eapp/group-pmp-crypto.c
  eapp/aes_core.c)
target_include_directories(group-pmp-mediabench-io-linkcheck PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/mediabench-ii/port)
target_compile_definitions(group-pmp-mediabench-io-linkcheck PRIVATE
  GROUP_PMP_MEDIABENCH_LINK_IO=1)
target_link_libraries(group-pmp-mediabench-io-linkcheck
  group-pmp-mediabench-media-io)

foreach(codec mpeg4 jp2 h264-enc h264-dec)
  add_group_pmp_eapp_sources(
    group-pmp-mediabench-${codec}-board
    group-pmp-mediabench-${codec}-board
    eapp/group-pmp-mediabench-board.c
    eapp/group-pmp-crypto.c
    eapp/aes_core.c)
  target_include_directories(group-pmp-mediabench-${codec}-board PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mediabench-ii/port)
  target_link_libraries(group-pmp-mediabench-${codec}-board
    group-pmp-mediabench-media-io
    group-pmp-mediabench-board-common
    group-pmp-mediabench-${codec} m)
endforeach()
target_compile_definitions(group-pmp-mediabench-mpeg4-board PRIVATE
  GROUP_PMP_MEDIA_BOARD_MPEG4=1)
target_compile_definitions(group-pmp-mediabench-jp2-board PRIVATE
  GROUP_PMP_MEDIA_BOARD_JP2=1)
target_compile_definitions(group-pmp-mediabench-h264-enc-board PRIVATE
  GROUP_PMP_MEDIA_BOARD_H264_ENC=1)
target_compile_definitions(group-pmp-mediabench-h264-dec-board PRIVATE
  GROUP_PMP_MEDIA_BOARD_H264_DEC=1)
target_link_libraries(group-pmp-mediabench-mpeg4-board
  ${CMAKE_CURRENT_BINARY_DIR}/mediabench-ii/ffmpeg-private/libavcodec/libavcodec.a
  ${CMAKE_CURRENT_BINARY_DIR}/mediabench-ii/ffmpeg-private/libavutil/libavutil.a
  m)
add_dependencies(group-pmp-mediabench-mpeg4-board
  group-pmp-mediabench-ffmpeg-build)

add_group_pmp_eapp_sources(
  group-pmp-aes-enclave-baseline
  group-pmp-aes-enclave-baseline
  eapp/group-pmp-aes-enclave-baseline.c
  eapp/aes_core.c)
configure_group_pmp_aes_target(group-pmp-aes-enclave-baseline)
if(GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS)
  add_group_pmp_eapp_sources(
    group-pmp-aes-master-encrypt
    group-pmp-aes-master-encrypt
    eapp/group-pmp-aes-master.c)
  target_compile_definitions(group-pmp-aes-master-encrypt PRIVATE
    GROUP_PMP_AES_OPERATION=GROUP_PMP_BENCH_AES_ENCRYPT)
  add_group_pmp_eapp_sources(
    group-pmp-aes-master-decrypt
    group-pmp-aes-master-decrypt
    eapp/group-pmp-aes-master.c)
  target_compile_definitions(group-pmp-aes-master-decrypt PRIVATE
    GROUP_PMP_AES_OPERATION=GROUP_PMP_BENCH_AES_DECRYPT)
  add_group_pmp_eapp_sources(
    group-pmp-aes-worker
    group-pmp-aes-worker
    eapp/group-pmp-aes-worker.c
    eapp/aes_core.c)
  configure_group_pmp_aes_target(group-pmp-aes-worker)
  add_group_pmp_eapp_sources(
    group-pmp-aes-scale-worker
    group-pmp-aes-scale-worker
    eapp/group-pmp-aes-scale-worker.c
    eapp/aes_core.c)
  configure_group_pmp_aes_target(group-pmp-aes-scale-worker)
  add_group_pmp_eapp(
    group-pmp-utm-bench
    eapp/group-pmp-utm-bench.c
    group-pmp-utm-bench)
endif()
if(GROUP_PMP_ENABLE_SPARK_SCHEDULER)
  if(NOT KEYSTONE_SDK_SRC_DIR OR
     NOT EXISTS "${KEYSTONE_SDK_SRC_DIR}/src/app/group_task.c")
    message(FATAL_ERROR
      "Spark scheduler experiment requires SDK src/app/group_task.c")
  endif()
  add_group_pmp_eapp_sources(
    group-pmp-task-master
    group-pmp-task-master
    eapp/group-pmp-task-master.c
    ${KEYSTONE_SDK_SRC_DIR}/src/app/group_task.c)
  target_compile_definitions(group-pmp-task-master PRIVATE
    GROUP_PMP_TASK_BATCHES=${GROUP_PMP_TASK_BATCHES})
  add_group_pmp_eapp(
    group-pmp-task-worker
    eapp/group-pmp-task-worker.c
    group-pmp-task-worker)
  target_compile_definitions(group-pmp-task-worker PRIVATE
    GROUP_PMP_TASK_BATCHES=${GROUP_PMP_TASK_BATCHES})
endif()

set(GROUP_PMP_HOST_LIB ${KEYSTONE_LIB_HOST})
set(GROUP_PMP_HOST_INCLUDE_DIRS
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge)

if(KEYSTONE_SDK_SRC_DIR AND EXISTS "${KEYSTONE_SDK_SRC_DIR}/src/host/Enclave.cpp")
  list(INSERT GROUP_PMP_HOST_INCLUDE_DIRS 0
    ${KEYSTONE_SDK_SRC_DIR}/include
    ${KEYSTONE_SDK_SRC_DIR}/include/host)

  set(GROUP_PMP_SDK_HOST_SOURCES
    ${KEYSTONE_SDK_SRC_DIR}/src/host/Enclave.cpp
    ${KEYSTONE_SDK_SRC_DIR}/src/host/KeystoneDevice.cpp
    ${KEYSTONE_SDK_SRC_DIR}/src/host/Memory.cpp
    ${KEYSTONE_SDK_SRC_DIR}/src/host/ElfFile.cpp
    ${KEYSTONE_SDK_SRC_DIR}/src/host/hash_util.cpp
    ${KEYSTONE_SDK_SRC_DIR}/src/host/PhysicalEnclaveMemory.cpp
    ${KEYSTONE_SDK_SRC_DIR}/src/host/elf.c
    ${KEYSTONE_SDK_SRC_DIR}/src/host/elf32.c
    ${KEYSTONE_SDK_SRC_DIR}/src/host/elf64.c
    ${KEYSTONE_SDK_SRC_DIR}/src/common/sha3.c)

  add_library(group-pmp-keystone-host-latest STATIC ${GROUP_PMP_SDK_HOST_SOURCES})
  target_include_directories(group-pmp-keystone-host-latest BEFORE PUBLIC
    ${KEYSTONE_SDK_SRC_DIR}/include
    ${KEYSTONE_SDK_SRC_DIR}/include/host
    ${KEYSTONE_SDK_DIR}/include)
  set(GROUP_PMP_HOST_LIB group-pmp-keystone-host-latest)
endif()

set(GROUP_PMP_RUNNER_SOURCES
  motivation/architecture.c
  host/group-pmp-test-runner.cpp
  host/sqlite-gantt-trace.cpp
  host/sqlite-io-range-trace.cpp
  host/sqlite-extent-io.cpp
  eapp/aes_core.c
  sqlite-bench-master/sqlite3.c)
# SQLite's generated amalgamation intentionally uses constructs that trigger
# several GCC-version-specific diagnostics under the project's global -Werror
# policy. Keep the exception source-local so first-party code remains strict.
set_source_files_properties(sqlite-bench-master/sqlite3.c PROPERTIES
  COMPILE_FLAGS "-w")
if(GROUP_PMP_ENABLE_SPARK_SCHEDULER)
  list(APPEND GROUP_PMP_RUNNER_SOURCES
    ${KEYSTONE_SDK_SRC_DIR}/src/app/group_task.c)
endif()
add_executable(group-pmp-test-runner ${GROUP_PMP_RUNNER_SOURCES})
configure_group_pmp_aes_target(group-pmp-test-runner)
target_include_directories(group-pmp-test-runner BEFORE PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/eapp
  ${GROUP_PMP_HOST_INCLUDE_DIRS})
target_compile_definitions(group-pmp-test-runner PRIVATE
  SQLITE_THREADSAFE=1
  SQLITE_OMIT_LOAD_EXTENSION=1
  SQLITE_DEFAULT_MEMSTATUS=0)
target_link_libraries(group-pmp-test-runner
  ${GROUP_PMP_HOST_LIB}
  ${KEYSTONE_LIB_EDGE}
  pthread)
set_target_properties(group-pmp-test-runner
  PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)

add_executable(group-pmp-mediabench-board-runner
  host/group-pmp-mediabench-board-runner.cpp
  eapp/group-pmp-crypto.c eapp/aes_core.c)
target_include_directories(group-pmp-mediabench-board-runner BEFORE PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/eapp
  ${CMAKE_CURRENT_SOURCE_DIR}/mediabench-ii/port
  ${GROUP_PMP_HOST_INCLUDE_DIRS})
target_link_libraries(group-pmp-mediabench-board-runner
  group-pmp-mediabench-media-io
  group-pmp-mediabench-host-io
  group-pmp-mediabench-board-common
  ${GROUP_PMP_HOST_LIB} ${KEYSTONE_LIB_EDGE} pthread)
set_target_properties(group-pmp-mediabench-board-runner PROPERTIES
  CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)

if(GROUP_PMP_ENABLE_NATIVE_AES_DIAGNOSTIC)
  find_package(OpenSSL REQUIRED)

  add_executable(aes-native-baseline
    host/aes-native-baseline.c
    eapp/aes_core.c)
  configure_group_pmp_aes_target(aes-native-baseline)
  target_include_directories(aes-native-baseline PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/eapp)
  target_link_libraries(aes-native-baseline dl)

  add_executable(crypto-native-baseline
    host/crypto-native-baseline.c
    eapp/aes_core.c
    ECC/ecdsa_p256_bench.c
    micro-ecc-master/uECC.c
    RSA/rsa2048_bench.c
    SHA-256/sha256.c
    SM/SM2/sm2_bench.c
    SM/SM2/sm2.c
    SM/SM3/sm3.c
    SM/SM4/sm4.c)
  configure_group_pmp_aes_target(crypto-native-baseline)
  target_compile_definitions(crypto-native-baseline PRIVATE
    uECC_WORD_SIZE=8
    uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0
    uECC_SUPPORTS_secp224r1=0
    uECC_SUPPORTS_secp256r1=1
    uECC_SUPPORTS_secp256k1=0
    uECC_SUPPORT_COMPRESSED_POINT=0)
  target_include_directories(crypto-native-baseline PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/eapp
    ${CMAKE_CURRENT_SOURCE_DIR}/ECC
    ${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc-master
    ${CMAKE_CURRENT_SOURCE_DIR}/RSA
    ${CMAKE_CURRENT_SOURCE_DIR}/SHA-256
    ${CMAKE_CURRENT_SOURCE_DIR}/SM/SM2
    ${CMAKE_CURRENT_SOURCE_DIR}/SM/SM3
    ${CMAKE_CURRENT_SOURCE_DIR}/SM/SM4)
  set_source_files_properties(
    SM/SM2/sm2.c
    SM/SM2/sm2_bench.c
    micro-ecc-master/uECC.c
    PROPERTIES COMPILE_FLAGS "-w")
  if(TARGET OpenSSL::Crypto)
    target_link_libraries(crypto-native-baseline OpenSSL::Crypto)
  else()
    target_include_directories(crypto-native-baseline PRIVATE
      ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(crypto-native-baseline ${OPENSSL_CRYPTO_LIBRARY})
  endif()
  # Keep the benchmark portable across target root filesystems with different
  # OpenSSL SONAMEs. rebuild-and-test.sh places the exact linked libcrypto in
  # deploy/lib when the toolchain only provides a shared OpenSSL build.
  set_target_properties(crypto-native-baseline PROPERTIES
    BUILD_RPATH "\$ORIGIN/lib"
    INSTALL_RPATH "\$ORIGIN/lib")
endif()

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(group-pmp-test-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

add_custom_target(group-pmp-test ALL
  DEPENDS
    group-pmp-motivation-worker
    group-pmp-kv-worker
    ${GROUP_PMP_RV8_TARGETS}
    group-pmp-security-aead
    group-pmp-crypto-compute-worker
    group-pmp-security-scan
    group-pmp-security-capture
    ${GROUP_PMP_SECURITY_ACCESS_TARGETS}
    group-pmp-mediabench-jpeg
    group-pmp-mediabench-mpeg4
    group-pmp-mediabench-jp2
    group-pmp-mediabench-h264-enc
    group-pmp-mediabench-h264-dec
    group-pmp-mediabench-media-io
    group-pmp-mediabench-host-io
    group-pmp-mediabench-board-common
    group-pmp-mediabench-board-runner
    group-pmp-mediabench-mpeg4-board
    group-pmp-mediabench-jp2-board
    group-pmp-mediabench-h264-enc-board
    group-pmp-mediabench-h264-dec-board
    group-pmp-mediabench-mpeg4-linkcheck
    group-pmp-mediabench-jp2-linkcheck
    group-pmp-mediabench-h264-enc-linkcheck
    group-pmp-mediabench-h264-dec-linkcheck
    group-pmp-mediabench-io-linkcheck
    group-pmp-private-probe
    group-pmp-timeslice-a
    group-pmp-timeslice-b
    group-pmp-timeslice-check
    group-pmp-lease-hold
    group-pmp-ocall-blocker
    group-pmp-mw-master-dispatch
    group-pmp-mw-worker
    group-pmp-mw-master-aggregate
    group-pmp-mw-master-miss
    group-pmp-mw-worker-dispatch-rw-denied
    group-pmp-mw-worker-cross-slice-fault
    group-pmp-mw-worker-slice0-fault
    group-pmp-mw-master-aggregate-rw-denied
    group-pmp-mw-no-acquire-fault
    group-pmp-mw-release-fault
    group-pmp-mw-hold-yield
    group-pmp-mw-inherit-fault
    group-pmp-mw-exec-fault
    group-pmp-mw-master-fault
    group-pmp-mixed-master
    group-pmp-mixed-worker
    group-pmp-sqlite-master
    group-pmp-sqlite-worker
    group-pmp-aes-enclave-baseline
    group-pmp-test-runner
    group-pmp-test-eyrie)

if(GROUP_PMP_ENABLE_LEGACY_PURE_AES_BENCHMARKS)
  add_dependencies(group-pmp-test
    group-pmp-aes-master-encrypt
    group-pmp-aes-master-decrypt
    group-pmp-aes-worker
    group-pmp-aes-scale-worker
    group-pmp-utm-bench)
endif()

if(GROUP_PMP_ENABLE_NATIVE_AES_DIAGNOSTIC)
  add_dependencies(group-pmp-test
    aes-native-baseline
    crypto-native-baseline)
endif()

if(GROUP_PMP_ENABLE_SPARK_SCHEDULER)
  add_dependencies(group-pmp-test
    group-pmp-task-master
    group-pmp-task-worker)
endif()

add_dependencies(examples group-pmp-test)
