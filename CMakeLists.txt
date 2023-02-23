cmake_minimum_required(VERSION 3.16)
project(dma_test)

set(CMAKE_CXX_STANDARD 14)
add_compile_options(-w)

message("CMAKE system processor: ${CMAKE_SYSTEM_PROCESSOR}")

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    set(ENV{PKG_CONFIG_PATH} "/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig")
else()
    set(ENV{PKG_CONFIG_PATH} "/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/x86_64-linux-gnu/pkgconfig")
endif ()

message("PKG path : $ENV{PKG_CONFIG_PATH}")

include(FindThreads)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GFLAGS REQUIRED gflags)
pkg_check_modules(DOCA_DMA REQUIRED doca-dma)
pkg_check_modules(DOCA_COMMON REQUIRED doca-common)
pkg_check_modules(JSON-C REQUIRED json-c)
pkg_check_modules(DOCA_ARGP REQUIRED doca-argp)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    add_executable(dma_dpu "")
    target_sources(dma_dpu PUBLIC
            #"main.cpp"
            "dma_common.cc"
            #"sender.cc"
            #"receiver.cc"t
            "histogram.cc"
            "common.cc"
            #"dma_host.cc"
            "dma_dpu.cc"
            "utils.cc"
            )
    target_include_directories(dma_dpu PUBLIC
            /opt/mellanox/doca/include
            ${GFLAGS_INCLUDE_DIRS}
            ${LIBPMEM_INCLUDE_DIRS}
            ${DOCA_DMA_INCLUDE_DIRS}
            ${DOCA_COMMON_INCLUDE_DIRS}
            ${JSON-C_INCLUDE_DIRS}
            ${DOCA_ARGP_INCLUDE_DIRS}
            .)
    target_link_directories(dma_dpu PUBLIC
            ${DOCA_DMA_LIBRARY_DIRS}
            ${DOCA_COMMON_LIBRARY_DIRS}
            ${DOCA_ARGP_LIBRARY_DIRS})
    target_link_libraries(dma_dpu
            ${GFLAGS_LIBRARIES}
            ${LIBPMEM_LIBRARIES}
            ${DOCA_DMA_LIBRARIES}
            ${DOCA_COMMON_LIBRARIES}
            ${DOCA_ARGP_LIBRARIES}
            ${CMAKE_THREAD_LIBS_INIT}
            ${JSON-C_LIBRARIES}
            -lbsd)
else ()
    pkg_check_modules(LIBPMEM REQUIRED libpmem)
    add_executable(dma_host "")
    target_sources(dma_host PUBLIC
            #"main.cpp"
            "dma_common.cc"
            #"sender.cc"
            #"receiver.cc"
            "histogram.cc"
            "common.cc"
            "dma_host.cc"
            #"dma_dpu.cc"
            "utils.cc"
            )
    target_include_directories(dma_host PUBLIC
            /opt/mellanox/doca/include
            ${GFLAGS_INCLUDE_DIRS}
            ${LIBPMEM_INCLUDE_DIRS}
            ${DOCA_DMA_INCLUDE_DIRS}
            ${DOCA_COMMON_INCLUDE_DIRS}
            ${JSON-C_INCLUDE_DIRS}
            ${DOCA_ARGP_INCLUDE_DIRS}
            .)

    message("DMA lib: ${LIBPMEM_LIBRARIES} ${DOCA_DMA_LIBRARIES}")
    message("DMA lib dirs: ${DOCA_DMA_LIBRARY_DIRS}")
    target_link_directories(dma_host PUBLIC
            ${DOCA_DMA_LIBRARY_DIRS}
            ${DOCA_COMMON_LIBRARY_DIRS}
            ${DOCA_ARGP_LIBRARY_DIRS})
    target_link_libraries(dma_host
            ${GFLAGS_LIBRARIES}
            ${LIBPMEM_LIBRARIES}
            ${DOCA_DMA_LIBRARIES}
            ${DOCA_COMMON_LIBRARIES}
            ${DOCA_ARGP_LIBRARIES}
            ${CMAKE_THREAD_LIBS_INIT}
            ${JSON-C_LIBRARIES}
            -lbsd)
endif ()




