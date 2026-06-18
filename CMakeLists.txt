cmake_minimum_required(VERSION 3.10)
project(CryptumApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ===== КУДА КЛАДЁМ ФАЙЛЫ =====
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/plugins)

# ===== ОСНОВНОЕ ПРИЛОЖЕНИЕ =====
add_executable(cryptum
    src/cryptum.cpp
    src/main.cpp
)

target_include_directories(cryptum PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(cryptum PRIVATE dl)

# ===== ПЛАГИНЫ =====
function(add_crypto_plugin NAME)
    file(GLOB SOURCES "algorithms/${NAME}/*.cpp")
    if(NOT SOURCES)
        message(WARNING "Не найдены файлы для алгоритма: ${NAME}")
        return()
    endif()
    add_library(${NAME} SHARED ${SOURCES})
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/algorithms/${NAME}
        ${CMAKE_SOURCE_DIR}/include
    )
    set_target_properties(${NAME} PROPERTIES
        PREFIX "lib"
        SUFFIX ".so"
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/plugins
    )
endfunction()

add_crypto_plugin(rc5)
add_crypto_plugin(threefish)
add_crypto_plugin(xtea)
add_crypto_plugin(gost)
add_crypto_plugin(gm)
add_library(blowfish SHARED
    algorithms/blowfish/export_blowfish.cpp
    algorithms/blowfish/blowfish.cpp
)
target_include_directories(blowfish PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/algorithms/blowfish
    ${CMAKE_SOURCE_DIR}/include
)
set_target_properties(blowfish PROPERTIES
    PREFIX "lib"
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/plugins
)