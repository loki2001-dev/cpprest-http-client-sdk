# cpprest-http-client-sdk

---
- Modern C++20 HTTP client SDK powered by Microsoft's cpprest library.
- Offering synchronous, asynchronous, and coroutine-based APIs.
- Designed for simplicity, performance, and reliability.

---

## Features
- Supports all HTTP methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`
- Automatic CORS Preflight handling: Works like a browser
- Three execution modes: Synchronous, Asynchronous, **C++20 Coroutines**
- Bearer Token Management: Easy authentication token handling
- JSON Support: Automatic JSON serialization/deserialization
- Configurable: Timeout, SSL, default headers, etc.
- Structured Logging: spdlog-based logging
- Comprehensive Tests: Google Test-based unit tests
- Exception Safety: Clear exception hierarchy
- **HTTP/2** Support: Modern, efficient transport with multiplexing
- **Connection Pool**: Optimized resource reuse for high-performance workloads

---

## Getting Started
### Prerequisites
- Linux (Ubuntu 20.04 or later recommended)
- Requires CMake 3.14 or later
- Requires C++20 or later compiler
- [cpprestsdk](https://github.com/microsoft/cpprestsdk)
- [googletest](https://github.com/google/googletest)
- [spdlog](https://github.com/gabime/spdlog) (included as a submodule)

---

## Build Instructions
### Setup and Installation
```bash
# Update package lists
sudo apt-get update

# Install dependencies
sudo apt-get install build-essential cmake pkg-config
sudo apt-get install libcpprest-dev libboost-all-dev libssl-dev libgtest-dev

# Build the project
. build_project.sh
```

---

## Running Tests Examples
```bash
# Basic example
./http_client_example

# Coroutine example
./http_client_coroutine_example

# gTEST example
./http_client_tests
```

---

## Project Structure
```
cpprest-http-client-sdk/
├── CMakeLists.txt              # CMake build configuration
├── include/cpprest_client/     # Header files
│   ├── IHttpClient.h           # HTTP client interface
│   ├── HttpClientLogger.h      # Logger implementation
│   ├── HttpClientImpl.h        # Implementation class
│   ├── HttpClientCo.h          # Coroutine implementation
│   ├── Exceptions.h            # Exception classes
│   └── Config.h                # Configuration struct
├── src/                        # Source files
│   ├── HttpClientImpl.cpp      # Implementation
│   └── HttpClientCo.cpp        # Coroutine implementation
├── examples/                   # Example code
│   ├── main.cpp                # Basic usage
│   └── main_co.cpp             # Coroutine example
├── tests/                      # Test code
│   └── HttpClientTests.cpp     # GTest unit tests
└── README.md                   # This file
```

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.