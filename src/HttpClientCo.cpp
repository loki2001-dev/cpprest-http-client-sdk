#include "../include/cpprest-client/HttpClientCo.h"
#include "../include/cpprest-client/HttpClientLogger.h"
#include <cpprest/uri.h>
#include <algorithm>
#include <future>

namespace cpprest_client {

    const std::unordered_set <std::string> HttpClientCo::_preflight_methods = {
            "PUT", "DELETE", "PATCH", "POST"
    };

    HttpClientCo::HttpClientCo(const HttpClientConfig &config)
            : _config(config) {
        _logger = HttpClientLogger::get_logger("http_client_co");
    }

    void HttpClientCo::update_config(const HttpClientConfig &config) {
        _config = config;
    }

    std::string HttpClientCo::build_url(const std::string &url) const {
        if (url.starts_with("http://") || url.starts_with("https://")) {
            return url;
        }

        if (_config.base_url.empty()) {
            throw MalformedUrlException("No base URL configured and relative URL provided: " + url);
        }

        std::string result = _config.base_url;
        if (!result.ends_with("/") && !url.starts_with("/")) {
            result += "/";
        }
        result += url;
        return result;
    }

    web::http::http_headers HttpClientCo::merge_headers(
            const std::unordered_map <std::string, std::string> &additional_headers) const {

        web::http::http_headers headers;
        for (const auto &[key, value]: _config.default_headers) {
            headers.add(utility::conversions::to_string_t(key), utility::conversions::to_string_t(value));
        }

        if (!_config.user_agent.empty()) {
            headers.add(web::http::header_names::user_agent, utility::conversions::to_string_t(_config.user_agent));
        }

        for (const auto &[key, value]: additional_headers) {
            headers.add(utility::conversions::to_string_t(key), utility::conversions::to_string_t(value));
        }

        return headers;
    }

    web::http::client::http_client_config HttpClientCo::create_client_config() const {
        web::http::client::http_client_config client_config;
        client_config.set_timeout(_config.connect_timeout + _config.read_timeout);
        if (!_config.verify_ssl) {
            client_config.set_validate_certificates(false);
        }
        return client_config;
    }

    HttpResult HttpClientCo::convert_response(const web::http::http_response &response) {
        HttpResult result;
        result.status_code = response.status_code();
        for (const auto &header: response.headers()) {
            result.headers[utility::conversions::to_utf8string(header.first)] = utility::conversions::to_utf8string(
                    header.second);
        }

        try {
            if (response.body()) {
                result.body = utility::conversions::to_utf8string(response.extract_string().get());
                if (result.is_json() && !result.body.empty()) {
                    result.json_body = web::json::value::parse(utility::conversions::to_string_t(result.body));
                }
            }
        } catch (const std::exception &e) {
            _logger->warn("Failed to parse response body: {}", e.what());
        }

        return result;
    }

    // Core
    pplx::task<bool> HttpClientCo::execute_preflight_co(const std::string &url,
                                                        web::http::method method,
                                                        const std::unordered_map <std::string, std::string> &headers) {
        try {
            web::http::client::http_client
            client(utility::conversions::to_string_t(build_url(url)), create_client_config());

            auto preflight_headers = merge_headers({});
            preflight_headers.add(U("Access-Control-Request-Method"), utility::conversions::to_string_t(method));

            std::vector <std::string> custom_headers;
            for (const auto &[key, value]: headers) {
                if (key != "content-type" && key != "authorization") {
                    custom_headers.push_back(key);
                }
            }

            if (!custom_headers.empty()) {
                std::string headers_str;
                for (size_t i = 0; i < custom_headers.size(); ++i) {
                    if (i > 0) {
                        headers_str += ", ";
                    }
                    headers_str += custom_headers[i];
                }
                preflight_headers.add(U("Access-Control-Request-Headers"),
                                      utility::conversions::to_string_t(headers_str));
            }

            web::http::http_request req(web::http::methods::OPTIONS);
            req.set_request_uri(U("/"));
            req.headers() = preflight_headers;

            return client.request(req).then([this](web::http::http_response response) -> bool {
                if (response.status_code() == 200 || response.status_code() == 204) {
                    _logger->debug("CORS preflight successful");
                    return true;
                }
                _logger->warn("CORS preflight failed with status: {}", response.status_code());
                return false;
            });
        } catch (const std::exception &e) {
            _logger->error("CORS preflight error: {}", e.what());
            return pplx::task_from_result(false);
        }
    }

    pplx::task<HttpResult> HttpClientCo::execute_request_co(const std::string &url,
                                                            web::http::method method,
                                                            const std::string &body,
                                                            const std::unordered_map<std::string, std::string> &headers) {
        try {
            std::string full_url = build_url(url);
            _logger->info("HTTP {} {}", utility::conversions::to_utf8string(method), full_url);

            auto client = std::make_shared<web::http::client::http_client>(
                    utility::conversions::to_string_t(full_url), create_client_config());

            std::string method_str = utility::conversions::to_utf8string(method);
            auto merged_headers = merge_headers(headers);

            auto send_request = [this, client, method, body, merged_headers]() -> pplx::task<HttpResult> {
                web::http::http_request req(method);

                // header
                for (const auto& [key, value] : merged_headers) {
                    req.headers().add(utility::conversions::to_string_t(key),
                                      utility::conversions::to_string_t(value));
                }

                // body
                if (!body.empty()) {
                    req.set_body(utility::conversions::to_string_t(body));
                }

                // request
                return client->request(req).then([this](web::http::http_response response) {
                    return convert_response(response);
                });
            };

            if (_preflight_methods.count(method_str) > 0) {
                return execute_preflight_co(url, method, headers).then(
                        [this, send_request](bool preflight_ok) -> pplx::task<HttpResult> {
                            if (!preflight_ok) {
                                _logger->warn("CORS preflight failed, proceeding with request anyway");
                            }
                            return send_request();
                        }
                );
            } else {
                return send_request();
            }

        } catch (const std::exception &e) {
            _logger->error("HTTP request failed: {}", e.what());
            return pplx::task_from_result(HttpResult{}); // 실패 시 기본값 반환
        }
    }

// Sync
#define DEFINE_SYNC_METHOD(NAME, METHOD) \
HttpResult HttpClientCo::NAME##_co(const std::string& url, const std::string& body, const std::unordered_map<std::string,std::string>& headers) { \
    return execute_request_co(url, METHOD, body, headers).get(); \
}

        DEFINE_SYNC_METHOD(get, web::http::methods::GET)

        DEFINE_SYNC_METHOD(post, web::http::methods::POST)

        DEFINE_SYNC_METHOD(put, web::http::methods::PUT)

        DEFINE_SYNC_METHOD(patch, web::http::methods::PATCH)

        DEFINE_SYNC_METHOD(del, web::http::methods::DEL)

        DEFINE_SYNC_METHOD(head, web::http::methods::HEAD)

        DEFINE_SYNC_METHOD(options, web::http::methods::OPTIONS)

// Async
#define DEFINE_ASYNC_METHOD(NAME, METHOD) \
std::future<HttpResult> HttpClientCo::NAME##_async(const std::string& url, const std::string& body, const std::unordered_map<std::string,std::string>& headers) { \
    auto task = execute_request_co(url, METHOD, body, headers); \
    return std::async(std::launch::async, [task]() { return task.get(); }); \
}

        DEFINE_ASYNC_METHOD(get, web::http::methods::GET)

        DEFINE_ASYNC_METHOD(post, web::http::methods::POST)

        DEFINE_ASYNC_METHOD(put, web::http::methods::PUT)

        DEFINE_ASYNC_METHOD(patch, web::http::methods::PATCH)

        DEFINE_ASYNC_METHOD(del, web::http::methods::DEL)

        DEFINE_ASYNC_METHOD(head, web::http::methods::HEAD)

        DEFINE_ASYNC_METHOD(options, web::http::methods::OPTIONS)

} // namespace cpprest_client