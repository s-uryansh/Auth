cmake_minimum_required(VERSION 3.20)
project(Auth VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(STRICT_CXX_FLAGS
  -Wall -Wextra -Werror -pedantic -Wshadow -Wnon-virtual-dtor)
set(SANITIZER_FLAGS
  -fsanitize=address -fno-omit-frame-pointer)

find_package(OpenSSL REQUIRED)
find_package(GTest CONFIG REQUIRED)

# ── Core library ──────────────────────────────────────────────────────────────
add_library(AuthLib
  src/Registration.cpp
  src/Authentication.cpp)

target_include_directories(AuthLib PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

target_link_libraries(AuthLib PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto)

target_compile_options(AuthLib PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
target_link_options(AuthLib    PRIVATE ${SANITIZER_FLAGS})

# ── Demo executable ───────────────────────────────────────────────────────────
add_executable(AuthApp src/main.cpp)
target_link_libraries(AuthApp PRIVATE AuthLib)
target_compile_options(AuthApp PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
target_link_options(AuthApp    PRIVATE ${SANITIZER_FLAGS})

# ── Tests — enable_testing() MUST come before add_executable for ctest ────────
enable_testing()

add_executable(AuthTests tests/test_auth.cpp)
target_link_libraries(AuthTests PRIVATE
  AuthLib
  GTest::gtest_main)   # gtest_main pulls gtest; no need to list both

target_compile_options(AuthTests PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
target_link_options(AuthTests    PRIVATE ${SANITIZER_FLAGS})

add_test(NAME AuthUnitTests COMMAND AuthTests)