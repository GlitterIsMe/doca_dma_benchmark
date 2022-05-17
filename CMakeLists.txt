cmake_minimum_required(VERSION 3.16)
project(dma_test)

set(CMAKE_CXX_STANDARD 14)

message("CMAKE system processor: ${CMAKE_SYSTEM_PROCESSOR}")

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    set(ENV{PKG_CONFIG_PATH} "/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig")
else()
    set(ENV{PKG_CONFIG_PATH} "/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig")
endif ()

message("PKG path : $ENV{PKG_CONFIG_PATH}")

include(FindThreads)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GFLAGS REQUIRED gflags)
pkg_check_modules(LIBPMEM REQUIRED libpmem)
pkg_check_modules(DOCA_DMA REQUIRED doca-dma)
pkg_check_modules(DOCA_COMMON REQUIRED doca-common)
pkg_check_modules(JSON-C REQUIRED json-c)

add_executable(dma_test main.cpp dma_common.cc sender.cc receiver.cc)
target_include_directories(dma_test PUBLIC
        /opt/mellanox/doca/include
        ${GFLAGS_INCLUDE_DIRS}
        ${LIBPMEM_INCLUDE_DIRS}
        ${DOCA_DMA_INCLUDE_DIRS}
        ${DOCA_COMMON_INCLUDE_DIRS}
        ${JSON-C_INCLUDE_DIRS}
        .)

message("DMA lib: ${LIBPMEM_LIBRARIES} ${DOCA_DMA_LIBRARIES}")
message("DMA lib dirs: ${DOCA_DMA_LIBRARY_DIRS}")
target_link_directories(dma_test PUBLIC
        ${DOCA_DMA_LIBRARY_DIRS}
        ${DOCA_COMMON_LIBRARY_DIRS})
target_link_libraries(dma_test
        ${GFLAGS_LIBRARIES}
        ${LIBPMEM_LIBRARIES}
        ${DOCA_DMA_LIBRARIES}
        ${DOCA_COMMON_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
        ${JSON-C_LIBRARIES})
