#pragma once

#include <stdexcept>
#include <string>

namespace cpprest_client {

    class HttpClientException : public std::runtime_error {
    public:
        explicit HttpClientException(const std::string& message)
            : std::runtime_error("HttpClient Error: " + message) {

        }
    };

    class NetworkException : public HttpClientException {
    public:
        explicit NetworkException(const std::string& message)
            : HttpClientException("Network Error: " + message) {

        }
    };

    class TimeoutException : public HttpClientException {
    public:
        explicit TimeoutException(const std::string& message)
            : HttpClientException("Timeout Error: " + message) {

        }
    };

    class HttpStatusException : public HttpClientException {
    private:
        int _status_code;
        std::string _response_body;

    public:
        HttpStatusException(int status_code, const std::string& message, const std::string& response_body = "")
            : HttpClientException("HTTP " + std::to_string(status_code) + ": " + message),
            status_code_(status_code),
            response_body_(response_body) {

        }

        int status_code() const noexcept {
            return _status_code;
        }

        const std::string& response_body() const noexcept {
            return _response_body;
        }
    };

    class JsonException : public HttpClientException {
    public:
        explicit JsonException(const std::string& message)
            : HttpClientException("JSON Error: " + message) {

        }
    };

    class SslException : public HttpClientException {
    public:
        explicit SslException(const std::string& message)
            : HttpClientException("SSL Error: " + message) {

        }
    };

    class InvalidUrlException : public HttpClientException {
    public:
        explicit InvalidUrlException(const std::string& url)
            : HttpClientException("Invalid URL: " + url) {

        }
    };

} // namespace cpprest_client