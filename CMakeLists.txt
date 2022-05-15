cmake_minimum_required(VERSION 2.6)
project(simple-dict-server C)
SET(CMAKE_BUILD_TYPE "Release")

add_definitions(-DLISTEN_ON_IPV6)
#add_definitions(-DDEBUG)
IF(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions("-DCPUBIT64")
ELSE()
    add_definitions("-DCPUBIT32")
ENDIF()

include_directories("/usr/local/include")
link_directories("/usr/local/lib")

#在编译选项中加入c99支持
add_compile_options(-std=gnu99)
message(STATUS "optional:-std=gnu99")

add_executable(simple-dict-server server.c)
add_executable(simple-dict-client client.c)
add_executable(cfgwriter cfgwriter.c)
#add_executable(migrate migrate.c)
#add_executable(migratenew migratenew.c)

target_link_libraries(simple-dict-server scrypto libspb.a pthread)
target_link_libraries(simple-dict-client scrypto libspb.a pthread)
target_link_libraries(cfgwriter libspb.a)

#target_link_libraries(migrate libspb.a)
#target_link_libraries(migratenew libspb.a)

INSTALL(TARGETS simple-dict-server RUNTIME DESTINATION bin)
#INSTALL(TARGETS simple-dict-client RUNTIME DESTINATION bin)
#INSTALL(TARGETS cfgwriter RUNTIME DESTINATION bin)