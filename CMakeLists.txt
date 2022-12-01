cmake_minimum_required (VERSION 3.0.0 FATAL_ERROR)

# ----------------------------------------------------------------------------
# package information
set (PACKAGE_NAME        "uNOVA")
set (PACKAGE_VERSION     "1.0")

project (${PACKAGE_NAME} VERSION ${PACKAGE_VERSION} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

MESSAGE(STATUS "Project: ${PACKAGE_NAME}")

# -fpic -fPIC
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -DERPC_INFINIBAND=true -D_FILE_OFFSET_BITS=64")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_compile_options(-g)
# add_definitions(-D NDEBUG)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O3")

set(INCLUDE_HEAD_LIST
    ${PROJECT_SOURCE_DIR}
)
include_directories(${INCLUDE_HEAD_LIST})

file(GLOB UTIL_SRC
    ${PROJECT_SOURCE_DIR}/util/*.cc
)
file(GLOB VFS_SRC
    ${PROJECT_SOURCE_DIR}/vfs/*.cc
)
file(GLOB HOOK_COM_SRC
    ${PROJECT_SOURCE_DIR}/syscall-intercept/*.cc
    ${VFS_SRC}
)
file(GLOB NOVA_SRC
    ${PROJECT_SOURCE_DIR}/nova/*.cc
)
file(GLOB FINEFS_SRC
    ${PROJECT_SOURCE_DIR}/finefs/*.cc
)

file(GLOB ALL_SRC
    ${UTIL_SRC}
    ${HOOK_COM_SRC}
    ${NOVA_SRC}
    ${FINEFS_SRC}
)


add_library(nova_hook SHARED ${ALL_SRC})
target_link_libraries(nova_hook
    syscall_intercept
    glog pthread numa pmem2
)
target_compile_definitions(nova_hook PRIVATE FS_HOOK=1)

add_library(finefs_hook SHARED ${ALL_SRC})
target_link_libraries(finefs_hook
    syscall_intercept
    glog pthread numa pmem2
)
target_compile_definitions(finefs_hook PRIVATE FS_HOOK=2)

# 一些测试和可运行文件

# set(HOOK_HEAD_LIST ${PROJECT_SOURCE_DIR})
# target_include_directories(demo_hook PUBLIC ${HOOK_HEAD_LIST})

# add_executable(fstest test/fstest.cc ${HOOK_SRC})
# target_link_libraries(fstest
#     pthread syscall_intercept
#     glog pthread numa pmem2
# )
add_executable(nova_fstest test/fstest.cc)
target_link_libraries(nova_fstest
    pthread syscall_intercept dl
)
target_compile_definitions(nova_fstest PRIVATE FS_HOOK=1)

add_executable(finefs_fstest test/fstest.cc)
target_link_libraries(finefs_fstest
    pthread syscall_intercept dl
)
target_compile_definitions(finefs_fstest PRIVATE FS_HOOK=2)

add_executable(nova_basic_test
    test/nova_basic_test.cc
    ${UTIL_SRC}
    ${VFS_SRC}
    ${NOVA_SRC}
    ${FINEFS_SRC}
)
target_link_libraries(nova_basic_test
    glog pthread numa pmem2
)
