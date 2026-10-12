cmake_minimum_required(VERSION 3.20)
project(Auth VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

# Detect build platform
if(CMAKE_ANDROID_NDK)
  message(STATUS "Building for ANDROID")
  set(CMAKE_SYSTEM_NAME Android)
  set(CMAKE_ANDROID_NDK "${CMAKE_ANDROID_NDK}")
  set(CMAKE_ANDROID_ARCH_arm NEAR FALSE CACHE STRING "Build for x86_64" FORCE)
  set(CMAKE_ANDROID_ARCH_AARCH64 NEAR FALSE CACHE STRING "Build for arm64-v8a" FORCE)
  set(CMAKE_ANDROID_ARCH_ARM NEAR FALSE CACHE STRING "Build for armeabi-v7a" FORCE)
  set(CMAKE_ANDROID_ARCH_X86 NEAR FALSE CACHE STRING "Build for x86" FORCE)
  set(CMAKE_ANDROID_PLATFORM "android-21")
else()
  message(STATUS "Building for HOST / DESKTOP")
endif()

# vcpkg dependencies
set(VCPKG_ROOT "${HOME}/vcpkg")

if(NOT CMAKE_ANDROID_NDK)
  list(APPEND CMAKE_PREFIX_PATH "${VCPKG_ROOT}/installed/x64-linux")
endif()

set(STRICT_CXX_FLAGS
  -Wall -Wextra -Werror -pedantic -Wshadow -Wnon-virtual-dtor)

set(SANITIZER_FLAGS
  -fsanitize=address -fno-omit-frame-pointer)

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(liboqs CONFIG REQUIRED)   # ML-KEM-768 (NIST FIPS 203)
find_package(GTest CONFIG REQUIRED)

# Core library
add_library(AuthLib
  src/Registration.cpp
  src/Authentication.cpp
  src/vault.cpp)

target_include_directories(AuthLib PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  /home/s-uryansh/Desktop/Codes/Auth/vcpkg_installed/x64-linux/include>
  /home/s-uryansh/vcpkg/packages/argon2_x64-linux/include)
target_include_directories(AuthLib PUBLIC
  $<INSTALL_INTERFACE:include>)

# Link argon2 statically from vcpkg build directory
set(ARGON2_LIBRARY "/home/s-uryansh/Desktop/Codes/Auth/vcpkg_installed/x64-linux/lib/libargon2.a")
target_link_libraries(AuthLib PRIVATE ${ARGON2_LIBRARY})

target_link_libraries(AuthLib PRIVATE
  OpenSSL::SSL
  OpenSSL::Crypto
  OQS::oqs)

target_compile_options(AuthLib PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
target_link_options(AuthLib    PRIVATE ${SANITIZER_FLAGS})

# Demo executable
add_executable(AuthUI src/main.cpp)
target_link_libraries(AuthUI PRIVATE AuthLib)
target_compile_options(AuthUI PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
target_link_options(AuthUI    PRIVATE ${SANITIZER_FLAGS})

# Tests (skip GTest-based unit tests for Android; keep AuthUI manual verification)
enable_testing()

if(NOT CMAKE_ANDROID_NDK)
  add_executable(AuthTests tests/test_auth.cpp)
  target_link_libraries(AuthTests PRIVATE
    AuthLib
    GTest::gtest_main)

  target_compile_options(AuthTests PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
  target_link_options(AuthTests    PRIVATE ${SANITIZER_FLAGS})

  add_test(NAME AuthUnitTests COMMAND AuthTests)
endif()

# Custom target: run AuthUI under ASan with system-library suppressions
add_custom_target(LSanCheck
  COMMAND ${CMAKE_COMMAND} -E env "LSAN_OPTIONS=suppressions=${CMAKE_SOURCE_DIR}/lsan.supp" ${CMAKE_BINARY_DIR}/AuthUI
  WORKDIR ${CMAKE_BINARY_DIR}
  COMMENT "Running AuthUI under ASan with system-library suppressions"
  VERBATIM
)

# Qt GUI application
if(CMAKE_ANDROID_NDK)
  message(STATUS "Configuring AuthQt for ANDROID")
  # For Android, use Qt's built-in Android generation
  find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui)
  # Android needs setuproot andandwaitfinish
  set(CMAKE_AUTOMOC ON)
  set(CMAKE_AUTORCC ON)
  set(CMAKE_AUTOUIC ON)
  # Note: Full Android build requires ANDROID_NDK_ROOT and ANDROID_API_LEVEL
  # The actual Android APK generation would use ANDROID_EXTRA_GRADLE_ARGS
  add_executable(AuthQt
    ui/main.cpp
    ui/AuthTab.cpp
    ui/AuthTab.h
    ui/MainWindow.cpp
    ui/MainWindow.h
    ui/PasswordManagerTab.cpp
    ui/PasswordManagerTab.h
    ui/QRSyncTab.cpp
    ui/QRSyncTab.h
  )
  # For Android, link Qt modules differently
  target_link_libraries(AuthQt PRIVATE Qt6::Widgets Qt6::Core Qt6::Gui AuthLib OQS::oqs)
  target_compile_options(AuthQt PRIVATE ${STRICT_CXX_FLAGS})
  target_link_options(AuthQt    PRIVATE ${SANITIZER_FLAGS})
else()
  find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui)
  add_executable(AuthQt
    ui/main.cpp
    ui/AuthTab.cpp
    ui/AuthTab.h
    ui/MainWindow.cpp
    ui/MainWindow.h
    ui/PasswordManagerTab.cpp
    ui/PasswordManagerTab.h
    ui/QRSyncTab.cpp
    ui/QRSyncTab.h
  )
  target_link_libraries(AuthQt PRIVATE Qt6::Widgets Qt6::Core Qt6::Gui AuthLib OQS::oqs)
  target_compile_options(AuthQt PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
  target_link_options(AuthQt    PRIVATE ${SANITIZER_FLAGS})
endif()

add_test(NAME AuthQtApp COMMAND AuthQt)