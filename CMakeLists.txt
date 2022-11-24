cmake_minimum_required (VERSION 3.0.0 FATAL_ERROR)

# ----------------------------------------------------------------------------
# package information
set (PACKAGE_NAME        "uNOVA")
set (PACKAGE_VERSION     "1.0")

project (${PACKAGE_NAME} VERSION ${PACKAGE_VERSION} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

MESSAGE(STATUS "Project: ${PACKAGE_NAME}")

add_compile_options(-g)
# add_definitions(-D NDEBUG)
# -fpic -fPIC
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -DERPC_INFINIBAND=true -D_FILE_OFFSET_BITS=64")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_compile_options(-g)
# add_definitions(-D NDEBUG)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O3")

set(INCLUDE_HEAD_LIST
    ${PROJECT_SOURCE_DIR}
    # ${PROJECT_SOURCE_DIR}/nova
    # ${PROJECT_SOURCE_DIR}/util
)
include_directories(${INCLUDE_HEAD_LIST})

file(GLOB HOOK_SRC
    ${PROJECT_SOURCE_DIR}/syscall-intercept/*.cc
)

file(GLOB UTIL_SRC
    ${PROJECT_SOURCE_DIR}/util/*.cc
)

file(GLOB UNOVA_SRC
    ${PROJECT_SOURCE_DIR}/nova/*.cc
)

set(HOOK_HEAD_LIST ${PROJECT_SOURCE_DIR})
add_library(demo_hook SHARED ${HOOK_SRC})
target_link_libraries(demo_hook
    pthread syscall_intercept
)
target_include_directories(demo_hook PUBLIC ${HOOK_HEAD_LIST})

add_executable(test test/fstest.cc)
target_link_libraries(test
    pthread syscall_intercept
)

add_executable(nova_basic_test
    test/nova_basic_test.cc
    ${UTIL_SRC}
    ${UNOVA_SRC}
)
target_link_libraries(nova_basic_test
    glog pthread numa pmem2
)
