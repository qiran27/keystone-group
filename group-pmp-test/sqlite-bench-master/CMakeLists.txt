cmake_minimum_required(VERSION 3.10)
project(sqlite-bench C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -O2 -DNDEBUG)
add_compile_definitions(
    SQLITE_ENABLE_MEMSYS5
    SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_THREADSAFE=0
)

add_executable(sqlite-bench
    benchmark.c
    histogram.c
    main.c
    random.c
    raw.c
    sqlite3.c
    util.c
)

target_include_directories(sqlite-bench PRIVATE "${CMAKE_CURRENT_LIST_DIR}")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv")
    target_sources(sqlite-bench PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/../sec-aesgcm-bench/jh7110_aes_gcm_user.c"
    )
    target_compile_definitions(sqlite-bench PRIVATE
        SQLITE_BENCH_RISCV_NATIVE=1
        SQLITE_BENCH_HAVE_SEC=1
    )
    target_include_directories(sqlite-bench PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/../sec-aesgcm-bench"
        "${CMAKE_CURRENT_LIST_DIR}/../common/enclave"
    )
    target_link_libraries(sqlite-bench
        pthread
        dl
        m
    )
else()
    target_compile_definitions(sqlite-bench PRIVATE
        SQLITE_BENCH_RISCV_NATIVE=0
        SQLITE_BENCH_HAVE_SEC=0
    )
    target_link_libraries(sqlite-bench pthread dl m)
endif()
