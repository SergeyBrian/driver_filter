cmake_minimum_required(VERSION 3.29)
project(driver_filter C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

set(CMAKE_C_STANDARD 11)

set(DRIVER_SRC
        src/driver/main.c
        # src/driver/RegistrationData.c
)

wdk_add_driver(DriverFilter ${DRIVER_SRC})
target_link_libraries(DriverFilter WDK::FLTMGR)

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
