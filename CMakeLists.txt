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
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

set(HOOK_HEAD_LIST
    ${PROJECT_SOURCE_DIR}
)

file(GLOB HOOK_SRC
    ${PROJECT_SOURCE_DIR}/syscall-intercept-demo/*.cc
)

file(GLOB TEST_SRC
    ${PROJECT_SOURCE_DIR}/test/*.cc
)

add_library(demo_hook SHARED ${HOOK_SRC})
target_link_libraries(demo_hook
    pthread syscall_intercept
)
target_include_directories(demo_hook PUBLIC ${HOOK_HEAD_LIST})

add_executable(test ${TEST_SRC})
target_link_libraries(test
    pthread syscall_intercept
)

