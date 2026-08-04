cmake_minimum_required(VERSION 3.10)
project(bmu_parser C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Флаги компиляции (аналог -O2 -Wall -Wno-deprecated-declarations)
add_compile_options(-O2 -Wall -Wno-deprecated-declarations)

# Исходники
set(SOURCES
    src/bmu.c
    src/farmhash64.c
    src/crc5.c
    src/r3_args.c
)

add_executable(bmu_parser ${SOURCES})

# OpenSSL (libcrypto)
find_package(OpenSSL REQUIRED)
target_link_libraries(bmu_parser PRIVATE OpenSSL::Crypto)

# Установка (опционально)
install(TARGETS bmu_parser RUNTIME DESTINATION bin)