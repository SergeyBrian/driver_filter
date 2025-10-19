cmake_minimum_required(VERSION 3.26)
project(driver_filter CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)
include(FetchContent)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 23)

FetchContent_Declare(
    sqlite3
    URL https://sqlite.org/2025/sqlite-amalgamation-3500400.zip
)
FetchContent_MakeAvailable(sqlite3)

set(DRIVER_SRC
    src/driver/main.c
)

set(USER_SRC
    src/user/main.cc
    src/user/interpreter.cc
)

set(SERVICE_SRC
    src/service/main.cc
    src/service/pipe.cc
    src/service/database.cc
)

set(
    DACL_SRC
    src/common/dacl/dacl.cc
    src/common/dacl/user.cc
    src/common/dacl/proto.cc
    src/common/dacl/internal.cc
)

set(UTILS_SRC
    src/utils/strconv.cc
)


add_library(sqlite3 STATIC
  ${sqlite3_SOURCE_DIR}/sqlite3.c
)

target_include_directories(sqlite3 PUBLIC
  ${sqlite3_SOURCE_DIR}
)

add_executable(DriverFilterService ${SERVICE_SRC} ${UTILS_SRC})
target_link_libraries(DriverFilterService dacl sqlite3)

add_executable(DriverFilterController ${USER_SRC} ${UTILS_SRC})
target_link_libraries(DriverFilterController dacl)

wdk_add_driver(DriverFilter ${DRIVER_SRC})
target_link_libraries(DriverFilter WDK::FLTMGR)

add_library(dacl STATIC ${DACL_SRC})

add_custom_command(
      TARGET DriverFilter PRE_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/src/driver_filter.inf ${CMAKE_CURRENT_BINARY_DIR}/DriverFilter.inf
)

add_custom_command(
      TARGET DriverFilter POST_BUILD
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMAND stampinf.exe -f DriverFilter.inf
)

add_custom_command(
      TARGET DriverFilter POST_BUILD
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/DriverFilter.sys C:/Users/sbski/share
      COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/DriverFilter.inf C:/Users/sbski/share
)

set_target_properties(DriverFilter PROPERTIES OUTPUT_NAME "DriverFilter")
set_target_properties(DriverFilterController PROPERTIES OUTPUT_NAME "DriverFilter")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

enable_language(C)
set_source_files_properties(src/driver/main.c PROPERTIES LANGUAGE C)
