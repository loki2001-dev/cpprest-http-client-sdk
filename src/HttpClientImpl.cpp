#include "../include/cpprest-client/HttpClientImpl.h"
#include "../include/cpprest-client/HttpClientLogger.h"
#include <cpprest/uri.h>
#include <algorithm>
#include <unordered_set>
#include <chrono>

namespace cpprest_client {

    // Connection Pool
    std::unordered_map <std::string, std::shared_ptr<web::http::client::http_client>> HttpClientImpl::_connection_pool;
    std::mutex HttpClientImpl::_pool_mutex;
    std::chrono::steady_clock::time_point HttpClientImpl::_last_cleanup = std::chrono::steady_clock::now();
    bool HttpClientImpl::_http2_warning_shown = false; // Add static flag to show warning only once

    // CORS preflight
    const std::unordered_set <std::string> HttpClientImpl::_preflight_methods = {
            "PUT", "DELETE", "PATCH", "POST"
    };

    HttpClientImpl::HttpClientImpl(const Config &config)
            : _config(config) {
        _logger = HttpClientLogger::get_logger("http_client");

        // Show HTTP/2 status only once during initialization
        if (_config.enable_http2 && !_http2_warning_shown) {
            _logger->warn("[HTTP2] HTTP/2 configuration requested but not supported by this cpprestsdk version");
            _logger->info("[HTTP2] Falling back to HTTP/1.1 with connection upgrade headers");
            _http2_warning_shown = true;
        }

        // Log connection pool status
        if (_config.enable_connection_pool) {
            _logger->info("[POOL] Connection pool enabled (max {} connections per host)", _config.max_connections_per_host);
        } else {
            _logger->info("[POOL] Connection pool disabled - creating new connections for each request");
        }

        // Periodic cleanup of expired connections
        cleanup_expired_connections();
    }

    void HttpClientImpl::setAuthentication(std::shared_ptr <IAuthenticationStrategy> auth) {
        _auth = std::move(auth);
    }

    void HttpClientImpl::update_config(const Config &config) {
        _config = config;

        // Clear connection pool if pool settings changed
        if (!config.enable_connection_pool) {
            std::lock_guard <std::mutex> lock(_pool_mutex);
            _connection_pool.clear();
            _logger->info("[POOL] Connection pool cleared due to configuration change");
        }
    }

    std::string HttpClientImpl::extract_base_url(const std::string &full_url) const {
        try {
            web::uri uri(utility::conversions::to_string_t(full_url));
            std::string scheme = utility::conversions::to_utf8string(uri.scheme());
            std::string host = utility::conversions::to_utf8string(uri.host());
            int port = uri.port();

            std::string base_url = scheme + "://" + host;
            if (port != 0 &&
                !((scheme == "http" && port == 80) || (scheme == "https" && port == 443))) {
                base_url += ":" + std::to_string(port);
            }
            return base_url;
        } catch (const std::exception &e) {
            _logger->warn("[URL] Failed to parse URL for base extraction: {}", e.what());
            return full_url;
        }
    }

    std::shared_ptr <web::http::client::http_client> HttpClientImpl::get_or_create_client(const std::string &base_url) {
        if (!_config.enable_connection_pool) {
            // Connection pool disabled, create new client each time
            _logger->debug("[POOL] Creating new connection (pool disabled)");
            return std::make_shared<web::http::client::http_client>(
                    utility::conversions::to_string_t(base_url),
                    create_client_config()
            );
        }

        std::lock_guard <std::mutex> lock(_pool_mutex);

        auto it = _connection_pool.find(base_url);
        if (it != _connection_pool.end()) {
            _logger->debug("[POOL] Reusing pooled connection for: {}", base_url);
            return it->second;
        }

        // Check pool size limit
        if (_connection_pool.size() >= _config.max_connections_per_host * 10) { // rough limit
            _logger->warn("[POOL] Connection pool size limit reached, clearing old connections");
            _connection_pool.clear();
        }

        // Create new client
        auto client = std::make_shared<web::http::client::http_client>(
                utility::conversions::to_string_t(base_url),
                create_client_config()
        );

        _connection_pool[base_url] = client;
        _logger->info("[POOL] Created new pooled connection for: {} (pool size: {})", base_url, _connection_pool.size());

        return client;
    }

    void HttpClientImpl::cleanup_expired_connections() {
        auto now = std::chrono::steady_clock::now();
        auto time_since_last_cleanup = std::chrono::duration_cast<std::chrono::minutes>(now - _last_cleanup);

        // Cleanup every 5 minutes
        if (time_since_last_cleanup.count() >= 5) {
            std::lock_guard <std::mutex> lock(_pool_mutex);

            size_t initial_size = _connection_pool.size();

            // For simplicity, clear all connections during cleanup
            // In a production environment, you might want to track connection age
            _connection_pool.clear();

            _last_cleanup = now;

            if (initial_size > 0) {
                _logger->info("[POOL] Cleaned up {} expired connections", initial_size);
            }
        }
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

        // HTTP/2 connection header (if enabled) - Note: Limited support in older cpprestsdk versions
        if (_config.enable_http2) {
            // Add connection upgrade headers (basic HTTP/2 signaling)
            headers.add(U("Connection"), U("Upgrade, HTTP2-Settings"));
            headers.add(U("Upgrade"), U("h2c"));
            _logger->debug("[HTTP2] HTTP/2 upgrade headers added to request");
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

        // Timeout settings
        client_config.set_timeout(_config.connect_timeout + _config.read_timeout);

        // SSL settings
        if (!_config.verify_ssl) {
            client_config.set_validate_certificates(false);
            _logger->debug("[SSL] Certificate validation disabled");
        }

        // Connection pool settings
        if (_config.enable_connection_pool && _config.enable_keep_alive) {
            // Note: set_guarantee_order is deprecated, but we'll handle it gracefully
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            try {
                client_config.set_guarantee_order(false); // Allow parallel requests
                _logger->debug("[KEEP_ALIVE] Keep-alive settings configured");
            } catch (...) {
                _logger->debug("[KEEP_ALIVE] Could not configure guarantee_order (method may not be available)");
            }
#pragma GCC diagnostic pop
        }

        // Compression settings - Note: set_compress is not available in older versions
        // Most modern servers handle compression automatically, so this is often not needed
        _logger->debug("[COMPRESSION] Compression handled by underlying HTTP implementation");

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

        // Log HTTP version if available
        auto version_header = response.headers().find(U("HTTP-Version"));
        if (version_header != response.headers().end()) {
            std::string version = utility::conversions::to_utf8string(version_header->second);
            _logger->debug("[PROTOCOL] Response received via {}", version);
        }

        // Response body
        if (response.body()) {
            result.body = utility::conversions::to_utf8string(response.extract_string().get());
            // Parse: JSON
            if (result.is_json() && !result.body.empty()) {
                try {
                    result.json_body = web::json::value::parse(utility::conversions::to_string_t(result.body));
                } catch (const web::json::json_exception &e) {
                    _logger->warn("[JSON] Failed to parse JSON response: {}", e.what());
                }
            }
        }

        return result;
    }

    pplx::task<bool> HttpClientImpl::execute_preflight(const std::string &url,
                                                       web::http::method method,
                                                       const std::unordered_map <std::string, std::string> &headers) {
        try {
            std::string full_url = build_url(url);
            std::string base_url = extract_base_url(full_url);

            auto client = get_or_create_client(base_url);

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

            // Extract path from full URL
            web::uri uri(utility::conversions::to_string_t(full_url));
            req.set_request_uri(uri.resource());

            _logger->debug("[CORS] Executing CORS preflight for {} {}", utility::conversions::to_utf8string(method), url);

            return client->request(req).then([this](web::http::http_response response) -> bool {
                if (response.status_code() == 200 || response.status_code() == 204) {
                    _logger->debug("[CORS] CORS preflight successful");
                    return true;
                }
                _logger->warn("[CORS] CORS preflight failed with status: {}", response.status_code());
                return false;
            });
        } catch (const std::exception &e) {
            _logger->error("[CORS] CORS preflight error: {}", e.what());
            return pplx::task_from_result(false);
        }
    }

    pplx::task <HttpResponse> HttpClientImpl::execute_request(const std::string &url,
                                                              web::http::method method,
                                                              const std::string &body,
                                                              const std::unordered_map <std::string, std::string> &headers) {
        try {
            std::string full_url = build_url(url);
            std::string base_url = extract_base_url(full_url);

            // Only log at info level for important requests, use debug for detailed logging
            _logger->info("[REQUEST] {} {} {}",
                          utility::conversions::to_utf8string(method),
                          full_url,
                          _config.enable_connection_pool ? "(pooled)" : "(new-conn)");

            // Get or create client from connection pool
            auto client = get_or_create_client(base_url);

            // CORS preflight
            std::string method_str = utility::conversions::to_utf8string(method);
            auto merged_headers = merge_headers(headers);

            auto send_request = [this, client, method, body, merged_headers, full_url]() -> pplx::task <HttpResponse> {
                web::http::http_request req(method);
                req.headers() = merged_headers;

                // Extract path from full URL for the request URI
                web::uri uri(utility::conversions::to_string_t(full_url));
                req.set_request_uri(uri.resource());

                if (!body.empty()) {
                    req.set_body(utility::conversions::to_string_t(body));
                    _logger->debug("[REQUEST] Body size: {} bytes", body.length());
                }

                // Apply authentication if available
                if (_auth) {
                    _auth->apply(req);
                }

                return client->request(req).then([this](web::http::http_response response) {
                    auto result = convert_response(response);
                    _logger->debug("[RESPONSE] Status: {} | Body size: {} bytes",
                                   result.status_code, result.body.length());
                    return result;
                });
            };

            if (_preflight_methods.count(method_str) > 0) {
                return execute_preflight(url, method, headers).then(
                        [this, send_request](bool preflight_ok) mutable -> pplx::task <HttpResponse> {
                            if (!preflight_ok) {
                                _logger->warn("[CORS] CORS preflight failed, proceeding with request anyway");
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
        _logger->error("[ERROR] HTTP request failed: {}", e.what());
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