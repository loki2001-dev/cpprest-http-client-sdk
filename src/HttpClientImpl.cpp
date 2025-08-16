#include "../include/cpprest-client/HttpClientImpl.h"
#include "../include/cpprest-client/HttpClientLogger.h"
#include <cpprest/uri.h>
#include <algorithm>
#include <unordered_set>

namespace cpprest_client {

    // CORS preflight
    const std::unordered_set <std::string> HttpClientImpl::_preflight_methods = {
            "PUT", "DELETE", "PATCH", "POST"
    };

    HttpClientImpl::HttpClientImpl(const Config &config)
            : _config(config) {
        _logger = HttpClientLogger::get_logger("http_client");
    }

    void HttpClientImpl::update_config(const Config &config) {
        _config = config;
    }

    std::string HttpClientImpl::build_url(const std::string &url) const {
        if (url.starts_with("http://") || url.starts_with("https://")) {
            return url;
        }

        if (_config.base_url.empty()) {
            throw InvalidUrlException("No base URL configured and relative URL provided: " + url);
        }

        std::string result = _config.base_url;
        if (!result.ends_with("/") && !url.starts_with("/")) {
            result += "/";
        }
        result += url;

        return result;
    }

    web::http::http_headers
    HttpClientImpl::merge_headers(const std::unordered_map <std::string, std::string> &additional_headers) const {
        web::http::http_headers headers;

        // Header
        for (const auto &[key, value]: _config.default_headers) {
            headers.add(utility::conversions::to_string_t(key),
                        utility::conversions::to_string_t(value));
        }

        // User-Agent 설정
        if (!_config.user_agent.empty()) {
            headers.add(web::http::header_names::user_agent,
                        utility::conversions::to_string_t(_config.user_agent));
        }

        // Header (additional)
        for (const auto &[key, value]: additional_headers) {
            headers.add(utility::conversions::to_string_t(key),
                        utility::conversions::to_string_t(value));
        }

        return headers;
    }

    web::http::client::http_client_config HttpClientImpl::create_client_config() const {
        web::http::client::http_client_config client_config;

        // timout
        client_config.set_timeout(_config.connect_timeout + _config.read_timeout);

        // SSL
        if (!_config.verify_ssl) {
            client_config.set_validate_certificates(false);
        }

        return client_config;
    }

    HttpResponse HttpClientImpl::convert_response(const web::http::http_response &response) {
        HttpResponse result;
        result.status_code = response.status_code();

        // Header
        for (const auto &header: response.headers()) {
            result.headers[utility::conversions::to_utf8string(header.first)] =
                    utility::conversions::to_utf8string(header.second);
        }

        // Response
        if (response.body()) {
            result.body = utility::conversions::to_utf8string(response.extract_string().get());
            // Parse: JSON
            if (result.is_json() && !result.body.empty()) {
                try {
                    result.json_body = web::json::value::parse(utility::conversions::to_string_t(result.body));
                } catch (const web::json::json_exception &e) {
                    _logger->warn("Failed to parse JSON response: {}", e.what());
                }
            }
        }

        return result;
    }

    pplx::task<bool> HttpClientImpl::execute_preflight(const std::string &url,
                                                       web::http::method method,
                                                       const std::unordered_map <std::string, std::string> &headers) {
        try {
            web::http::client::http_client
            client(utility::conversions::to_string_t(build_url(url)), create_client_config());

            // request header: preflight
            auto preflight_headers = merge_headers({});
            preflight_headers.add(U("Access-Control-Request-Method"), utility::conversions::to_string_t(method));

            // Access-Control-Request-Headers
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

            // http_request 객체를 만들어서 OPTIONS 요청
            web::http::http_request req(web::http::methods::OPTIONS);
            req.headers() = preflight_headers;
            req.set_request_uri(U("/")); // root

            return client.request(req).then([this](web::http::http_response response) -> bool {
                if (response.status_code() == 200 || response.status_code() == 204) {
                    _logger->info("CORS preflight successful");
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

    pplx::task <HttpResponse> HttpClientImpl::execute_request(const std::string &url,
                                                              web::http::method method,
                                                              const std::string &body,
                                                              const std::unordered_map <std::string, std::string> &headers) {
        try {
            std::string full_url = build_url(url);
            _logger->info("HTTP {} {}", utility::conversions::to_utf8string(method), full_url);

            web::http::client::http_client client(utility::conversions::to_string_t(full_url), create_client_config());

            // CORS preflight
            std::string method_str = utility::conversions::to_utf8string(method);
            auto merged_headers = merge_headers(headers);

            auto send_request = [this, client, method, body, merged_headers]() mutable -> pplx::task <HttpResponse> {
                web::http::http_request req(method);
                req.headers() = merged_headers;

                if (!body.empty()) {
                    req.set_body(utility::conversions::to_string_t(body));
                }

                return client.request(req).then([this](web::http::http_response response) {
                    return convert_response(response);
                });
            };

            if (_preflight_methods.count(method_str) > 0) {
                return execute_preflight(url, method, headers).then(
                        [this, send_request](bool preflight_ok) mutable -> pplx::task <HttpResponse> {
                            if (!preflight_ok) {
                                _logger->warn("CORS preflight failed, proceeding with request anyway");
                            }
                            return send_request();
                        });
            } else {
                return send_request();
            }
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    void HttpClientImpl::handle_exception(const std::exception &e) const {
        _logger->error("HTTP request failed: {}", e.what());
        if (dynamic_cast<const web::http::http_exception *>(&e)) {
            throw NetworkException(e.what());
        }
    }

    // Sync
    HttpResponse HttpClientImpl::get(const std::string &url,
                                     const std::unordered_map <std::string, std::string> &headers) {
        try {
            return execute_request(url, web::http::methods::GET, "", headers).get();
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    HttpResponse HttpClientImpl::post(const std::string &url,
                                      const std::string &body,
                                      const std::unordered_map <std::string, std::string> &headers) {
        try {
            return execute_request(url, web::http::methods::POST, body, headers).get();
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    HttpResponse HttpClientImpl::post_json(const std::string &url,
                                           const web::json::value &json,
                                           const std::unordered_map <std::string, std::string> &headers) {
        auto json_headers = headers;
        json_headers["Content-Type"] = "application/json";

        std::string body = utility::conversions::to_utf8string(json.serialize());
        return post(url, body, json_headers);
    }

    HttpResponse HttpClientImpl::put(const std::string &url,
                                     const std::string &body,
                                     const std::unordered_map <std::string, std::string> &headers) {
        try {
            return execute_request(url, web::http::methods::PUT, body, headers).get();
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    HttpResponse HttpClientImpl::put_json(const std::string &url,
                                          const web::json::value &json,
                                          const std::unordered_map <std::string, std::string> &headers) {
        auto json_headers = headers;
        json_headers["Content-Type"] = "application/json";

        std::string body = utility::conversions::to_utf8string(json.serialize());
        return put(url, body, json_headers);
    }

    HttpResponse HttpClientImpl::patch(const std::string &url,
                                       const std::string &body,
                                       const std::unordered_map <std::string, std::string> &headers) {
        try {
            return execute_request(url, web::http::methods::PATCH, body, headers).get();
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    HttpResponse HttpClientImpl::patch_json(const std::string &url,
                                            const web::json::value &json,
                                            const std::unordered_map <std::string, std::string> &headers) {
        auto json_headers = headers;
        json_headers["Content-Type"] = "application/json";

        std::string body = utility::conversions::to_utf8string(json.serialize());
        return patch(url, body, json_headers);
    }

    HttpResponse HttpClientImpl::del(const std::string &url,
                                     const std::unordered_map <std::string, std::string> &headers) {
        try {
            return execute_request(url, web::http::methods::DEL, "", headers).get();
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    HttpResponse HttpClientImpl::head(const std::string &url,
                                      const std::unordered_map <std::string, std::string> &headers) {
        try {
            return execute_request(url, web::http::methods::HEAD, "", headers).get();
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    HttpResponse HttpClientImpl::options(const std::string &url,
                                         const std::unordered_map <std::string, std::string> &headers) {
        try {
            return execute_request(url, web::http::methods::OPTIONS, "", headers).get();
        } catch (const std::exception &e) {
            handle_exception(e);
            throw;
        }
    }

    // Async
    std::future <HttpResponse> HttpClientImpl::get_async(const std::string &url,
                                                         const std::unordered_map <std::string, std::string> &headers) {
        auto task = execute_request(url, web::http::methods::GET, "", headers);
        return std::async(std::launch::async, [task]() {
            return task.get();
        });
    }

    std::future <HttpResponse> HttpClientImpl::post_async(const std::string &url,
                                                          const std::string &body,
                                                          const std::unordered_map <std::string, std::string> &headers) {
        auto task = execute_request(url, web::http::methods::POST, body, headers);
        return std::async(std::launch::async, [task]() {
            return task.get();
        });
    }

    std::future <HttpResponse> HttpClientImpl::post_json_async(const std::string &url,
                                                               const web::json::value &json,
                                                               const std::unordered_map <std::string, std::string> &headers) {
        auto json_headers = headers;
        json_headers["Content-Type"] = "application/json";

        std::string body = utility::conversions::to_utf8string(json.serialize());
        return post_async(url, body, json_headers);
    }

    std::future <HttpResponse> HttpClientImpl::put_async(const std::string &url,
                                                         const std::string &body,
                                                         const std::unordered_map <std::string, std::string> &headers) {
        auto task = execute_request(url, web::http::methods::PUT, body, headers);
        return std::async(std::launch::async, [task]() { return task.get(); });
    }

    std::future <HttpResponse> HttpClientImpl::put_json_async(const std::string &url,
                                                              const web::json::value &json,
                                                              const std::unordered_map <std::string, std::string> &headers) {
        auto json_headers = headers;
        json_headers["Content-Type"] = "application/json";

        std::string body = utility::conversions::to_utf8string(json.serialize());
        return put_async(url, body, json_headers);
    }

    std::future <HttpResponse> HttpClientImpl::patch_async(const std::string &url,
                                                           const std::string &body,
                                                           const std::unordered_map <std::string, std::string> &headers) {
        auto task = execute_request(url, web::http::methods::PATCH, body, headers);
        return std::async(std::launch::async, [task]() {
            return task.get();
        });
    }

    std::future <HttpResponse> HttpClientImpl::patch_json_async(const std::string &url,
                                                                const web::json::value &json,
                                                                const std::unordered_map <std::string, std::string> &headers) {
        auto json_headers = headers;
        json_headers["Content-Type"] = "application/json";

        std::string body = utility::conversions::to_utf8string(json.serialize());
        return patch_async(url, body, json_headers);
    }

    std::future <HttpResponse> HttpClientImpl::del_async(const std::string &url,
                                                         const std::unordered_map <std::string, std::string> &headers) {
        auto task = execute_request(url, web::http::methods::DEL, "", headers);
        return std::async(std::launch::async, [task]() {
            return task.get();
        });
    }

    std::future <HttpResponse> HttpClientImpl::head_async(const std::string &url,
                                                          const std::unordered_map <std::string, std::string> &headers) {
        auto task = execute_request(url, web::http::methods::HEAD, "", headers);
        return std::async(std::launch::async, [task]() {
            return task.get();
        });
    }

    std::future <HttpResponse> HttpClientImpl::options_async(const std::string &url,
                                                             const std::unordered_map <std::string, std::string> &headers) {
        auto task = execute_request(url, web::http::methods::OPTIONS, "", headers);
        return std::async(std::launch::async, [task]() {
            return task.get();
        });
    }
} // namespace cpprest_client