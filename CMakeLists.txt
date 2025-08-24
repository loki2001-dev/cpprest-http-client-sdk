CMAKE_MINIMUM_REQUIRED(VERSION 3.15)
PROJECT(cpprest-http-client-sdk VERSION 1.0.0)

IF(POLICY CMP0167)
    CMAKE_POLICY(SET CMP0167 NEW)
ENDIF()

SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

# OPTION (3rdparty)
SET(BUILD_SHARED_LIBS ON CACHE BOOL "Build shared libraries by default")

ADD_COMPILE_OPTIONS(-Wall -Wextra -Wpedantic)

FIND_PACKAGE(PkgConfig REQUIRED)
FIND_PACKAGE(Boost REQUIRED COMPONENTS system filesystem thread chrono)
FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(cpprestsdk REQUIRED)

ADD_SUBDIRECTORY(3rdparty/loki-secure-sdk)
#ADD_SUBDIRECTORY(3rdparty/spdlog)

ADD_LIBRARY(cpprest-http-client-sdk
        src/HttpClientImpl.cpp
        src/HttpClientCo.cpp
        src/DigestAuth.cpp
)

TARGET_INCLUDE_DIRECTORIES(cpprest-http-client-sdk PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

TARGET_LINK_LIBRARIES(cpprest-http-client-sdk PUBLIC
        cpprestsdk::cpprest
        Boost::system
        Boost::filesystem
        Boost::thread
        Boost::chrono
        OpenSSL::SSL
        OpenSSL::Crypto
        loki-secure-sdk
        spdlog::spdlog
)

TARGET_COMPILE_DEFINITIONS(cpprest-http-client-sdk PUBLIC ${CPPREST_CFLAGS_OTHER})

# EXAMPLE
OPTION(BUILD_EXAMPLES "Build examples" ON)
IF(BUILD_EXAMPLES)
    ADD_EXECUTABLE(http_client_example
            example/main.cpp
            src/DigestAuth.cpp
    )

    TARGET_LINK_LIBRARIES(http_client_example PRIVATE
            cpprest-http-client-sdk
    )

    ADD_EXECUTABLE(http_client_coroutine_example
            example/main_co.cpp
    )

    TARGET_LINK_LIBRARIES(http_client_coroutine_example PRIVATE
            cpprest-http-client-sdk
    )
ENDIF()

# TEST(TDD)
OPTION(BUILD_TESTS "Build tests" ON)
IF(BUILD_TESTS)
    FIND_PACKAGE(GTest REQUIRED)
    ENABLE_TESTING()

    ADD_EXECUTABLE(http_client_tests test/HttpClientTests.cpp)
    TARGET_LINK_LIBRARIES(http_client_tests PRIVATE
            cpprest-http-client-sdk
            GTest::gtest
            GTest::gtest_main
    )

    ADD_TEST(NAME HttpClientTests COMMAND http_client_tests)
ENDIF()

# INSTALL RULE
IF(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    INSTALL(TARGETS cpprest-http-client-sdk EXPORT cpprest-http-client-sdkTargets
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
            RUNTIME DESTINATION bin
    )

    INSTALL(DIRECTORY include/ DESTINATION include)

    INSTALL(EXPORT cpprest-http-client-sdkTargets
            FILE cpprest-http-client-sdkTargets.cmake
            NAMESPACE cpprest-http-client-sdk::
            DESTINATION lib/cmake/cpprest-http-client-sdk
    )

    # CMake CONFIG
    INCLUDE(CMakePackageConfigHelpers)
    CONFIGURE_PACKAGE_CONFIG_FILE(
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cpprest_clientConfig.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cpprest_clientConfig.cmake"
            INSTALL_DESTINATION lib/cmake/cpprest-http-client-sdk
    )

    WRITE_BASIC_PACKAGE_VERSION_FILE(
            "${CMAKE_CURRENT_BINARY_DIR}/cpprest_clientConfigVersion.cmake"
            VERSION ${PROJECT_VERSION}
            COMPATIBILITY SameMajorVersion
    )

    INSTALL(FILES
            "${CMAKE_CURRENT_BINARY_DIR}/cpprest_clientConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/cpprest_clientConfigVersion.cmake"
            DESTINATION lib/cmake/cpprest-http-client-sdk
    )
ENDIF()