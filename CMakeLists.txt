cmake_minimum_required(VERSION 2.6)
project(simple-dict-server C)
SET(CMAKE_BUILD_TYPE "Release")

add_definitions(-DLISTEN_ON_IPV6)
# add_definitions(-DDEBUG)
IF(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions("-DCPUBIT64")
ELSE()
    add_definitions("-DCPUBIT32")
ENDIF()

include_directories("/usr/local/include")
link_directories("/usr/local/lib")

add_executable(simple-dict-server server.c dict.c crypto.c)
add_executable(simple-dict-client client.c crypto.c)
add_executable(migrate migrate.c)
add_executable(cfgwriter cfgwriter.c)

target_link_libraries(simple-dict-server scrypto spb pthread)
target_link_libraries(simple-dict-client scrypto pthread)
target_link_libraries(migrate spb)
target_link_libraries(cfgwriter spb)

INSTALL(TARGETS simple-dict-server RUNTIME DESTINATION bin)
#INSTALL(TARGETS simple-dict-client RUNTIME DESTINATION bin)
#INSTALL(TARGETS migrate RUNTIME DESTINATION bin)
#INSTALL(TARGETS cfgwriter RUNTIME DESTINATION bin)