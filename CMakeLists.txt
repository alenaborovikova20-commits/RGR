cmake_minimum_required(VERSION 3.10)
project(Cryptum)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -fPIC")

include_directories(include)
include_directories(src)

add_library(rc5 SHARED algorithms/RC5/rc5.cpp algorithms/RC5/export_rc5.cpp)
target_include_directories(rc5 PRIVATE algorithms/RC5)

add_library(threefish SHARED algorithms/threefish/threefish.cpp algorithms/threefish/export_threefish.cpp)
target_include_directories(threefish PRIVATE algorithms/threefish)

add_library(xtea SHARED algorithms/xtea/xtea.cpp algorithms/xtea/export_xtea.cpp)
target_include_directories(xtea PRIVATE algorithms/xtea)

add_library(gost SHARED algorithms/gost/gost.cpp algorithms/gost/export_gost.cpp)
target_include_directories(gost PRIVATE algorithms/gost)

add_library(gm SHARED algorithms/gm/gm.cpp algorithms/gm/export_gm.cpp)
target_include_directories(gm PRIVATE algorithms/gm)

add_library(mo SHARED algorithms/mo/mo.cpp algorithms/mo/export_mo.cpp)
target_include_directories(mo PRIVATE algorithms/mo)

add_executable(cryptum src/main.cpp src/cryptum.cpp)
target_link_libraries(cryptum dl)
target_include_directories(cryptum PRIVATE src)