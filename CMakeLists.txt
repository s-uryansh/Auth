cmake_minimum_required(VERSION 3.20)

project(Auth VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

set(STRICT_CXX_FLAGS -Wall -Wextra -Werror -pedantic -Wshadow -Wnon-virtual-dtor)
find_package(OpenSSL REQUIRED)
find_package(liboqs CONFIG REQUIRED)
find_package(unofficial-argon2 CONFIG REQUIRED)

add_library(AuthLib src/Registration.cpp src/Authentication.cpp src/vault.cpp)
target_include_directories(AuthLib PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(AuthLib PRIVATE OpenSSL::SSL OpenSSL::Crypto OQS::oqs unofficial::argon2::libargon2)
target_compile_options(AuthLib PRIVATE ${STRICT_CXX_FLAGS})

set(AUTH_QT_SOURCES
  ui/main.cpp ui/AuthTab.cpp ui/AuthTab.h ui/MainWindow.cpp ui/MainWindow.h
  ui/PasswordManagerTab.cpp ui/PasswordManagerTab.h
  ui/SensitiveData.cpp ui/SensitiveData.h
  ui/PasswordVaultFileStore.cpp ui/PasswordVaultFileStore.h
  ui/QRSyncTab.cpp ui/QRSyncTab.h)

if(ANDROID)
  find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui)
  # This app stores data in its private app directory and opens URLs with an
  # external handler, so Qt Core's broad network/public-storage permissions
  # are not needed in the APK.
  set_property(TARGET Qt6::Core PROPERTY QT_ANDROID_PERMISSIONS "")
  set_property(TARGET Qt6::Core PROPERTY INTERFACE_QT_ANDROID_PERMISSIONS "")
  qt_policy(SET QTP0002 NEW)
  qt_add_executable(AuthQt MANUAL_FINALIZATION ${AUTH_QT_SOURCES})
  target_link_libraries(AuthQt PRIVATE Qt6::Widgets Qt6::Core Qt6::Gui AuthLib OQS::oqs)
  target_compile_options(AuthQt PRIVATE ${STRICT_CXX_FLAGS})
  set_target_properties(AuthQt PROPERTIES
    QT_ANDROID_PACKAGE_NAME "org.tmps.auth"
    QT_ANDROID_MIN_SDK_VERSION "30"
    QT_ANDROID_TARGET_SDK_VERSION "30"
    QT_ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
  qt_finalize_executable(AuthQt)
else()
  list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg_installed/x64-linux")
  find_package(GTest CONFIG REQUIRED)
  find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui)

  set(SANITIZER_FLAGS -fsanitize=address -fno-omit-frame-pointer)
  add_executable(AuthUI src/main.cpp)
  target_link_libraries(AuthUI PRIVATE AuthLib)
  target_compile_options(AuthUI PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
  target_link_options(AuthUI PRIVATE ${SANITIZER_FLAGS})

  add_executable(AuthTests tests/test_auth.cpp)
  target_link_libraries(AuthTests PRIVATE AuthLib GTest::gtest_main)
  target_compile_options(AuthTests PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
  target_link_options(AuthTests PRIVATE ${SANITIZER_FLAGS})
  enable_testing()
  add_test(NAME AuthUnitTests COMMAND AuthTests)

  add_executable(SensitiveDataTests tests/test_sensitive_data.cpp ui/SensitiveData.cpp)
  target_include_directories(SensitiveDataTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_link_libraries(SensitiveDataTests PRIVATE Qt6::Core OpenSSL::Crypto GTest::gtest_main)
  target_compile_options(SensitiveDataTests PRIVATE ${STRICT_CXX_FLAGS})
  add_test(NAME SensitiveDataTests COMMAND SensitiveDataTests)

  add_executable(VaultStorageTests
    tests/test_vault_storage.cpp
    ui/PasswordVaultFileStore.cpp
    ui/PasswordVaultFileStore.h)
  target_include_directories(VaultStorageTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/ui)
  target_link_libraries(VaultStorageTests PRIVATE
    AuthLib Qt6::Core GTest::gtest_main)
  target_compile_options(VaultStorageTests PRIVATE ${STRICT_CXX_FLAGS})
  add_test(NAME VaultStorageTests COMMAND VaultStorageTests)

  add_custom_target(LSanCheck
    COMMAND ${CMAKE_COMMAND} -E env "LSAN_OPTIONS=suppressions=${CMAKE_SOURCE_DIR}/lsan.supp" ${CMAKE_BINARY_DIR}/AuthUI
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running AuthUI under ASan with system-library suppressions"
    VERBATIM)

  add_executable(AuthQt ${AUTH_QT_SOURCES})
  target_link_libraries(AuthQt PRIVATE Qt6::Widgets Qt6::Core Qt6::Gui AuthLib OQS::oqs)
  target_compile_options(AuthQt PRIVATE ${STRICT_CXX_FLAGS} ${SANITIZER_FLAGS})
  target_link_options(AuthQt PRIVATE ${SANITIZER_FLAGS})
endif()
