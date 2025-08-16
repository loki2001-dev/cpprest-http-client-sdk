#pragma once

#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <future>
#include <pplx/pplxtasks.h>
#include <spdlog/spdlog.h>
#include <unordered_map>
#include <unordered_set>
#include <string>

namespace cpprest_client {

    struct HttpResult {
        int status_code{0};
        std::string body;
        web::json::value json_body;
        std::unordered_map <std::string, std::string> headers;

        bool is_json() const {
            return !json_body.is_null();
        }

        bool is_success() const {
            return status_code >= 200 && status_code < 300;
        }
    };

    struct HttpClientConfig {
        std::string base_url;
        std::unordered_map <std::string, std::string> default_headers;
        std::string user_agent;
        bool verify_ssl{true};
        std::chrono::seconds connect_timeout{5};
        std::chrono::seconds read_timeout{10};
    };

    class MalformedUrlException : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class HttpClientCo {
    public:
        explicit HttpClientCo(const HttpClientConfig &config);

        void update_config(const HttpClientConfig &config);

        // Methods: Core
        pplx::task<bool> execute_preflight_co(
                const std::string &url,
                web::http::method method,
                const std::unordered_map <std::string, std::string> &headers);

        pplx::task <HttpResult> execute_request_co(
                const std::string &url,
                web::http::method method,
                const std::string &body = "",
                const std::unordered_map <std::string, std::string> &headers = {});

        // Methods: Sync
        HttpResult get_co(const std::string &url,
                          const std::string &body = "",
                          const std::unordered_map <std::string, std::string> &headers = {});

        HttpResult post_co(const std::string &url,
                           const std::string &body = "",
                           const std::unordered_map <std::string, std::string> &headers = {});

        HttpResult put_co(const std::string &url,
                          const std::string &body = "",
                          const std::unordered_map <std::string, std::string> &headers = {});

        HttpResult patch_co(const std::string &url,
                            const std::string &body = "",
                            const std::unordered_map <std::string, std::string> &headers = {});

        HttpResult del_co(const std::string &url,
                          const std::string &body = "",
                          const std::unordered_map <std::string, std::string> &headers = {});

        HttpResult head_co(const std::string &url,
                           const std::string &body = "",
                           const std::unordered_map <std::string, std::string> &headers = {});

        HttpResult options_co(const std::string &url,
                              const std::string &body = "",
                              const std::unordered_map <std::string, std::string> &headers = {});

        // // Methods: Async
        std::future <HttpResult> get_async(const std::string &url,
                                           const std::string &body = "",
                                           const std::unordered_map <std::string, std::string> &headers = {});

        std::future <HttpResult> post_async(const std::string &url,
                                            const std::string &body = "",
                                            const std::unordered_map <std::string, std::string> &headers = {});

        std::future <HttpResult> put_async(const std::string &url,
                                           const std::string &body = "",
                                           const std::unordered_map <std::string, std::string> &headers = {});

        std::future <HttpResult> patch_async(const std::string &url,
                                             const std::string &body = "",
                                             const std::unordered_map <std::string, std::string> &headers = {});

        std::future <HttpResult> del_async(const std::string &url,
                                           const std::string &body = "",
                                           const std::unordered_map <std::string, std::string> &headers = {});

        std::future <HttpResult> head_async(const std::string &url,
                                            const std::string &body = "",
                                            const std::unordered_map <std::string, std::string> &headers = {});

        std::future <HttpResult> options_async(const std::string &url,
                                               const std::string &body = "",
                                               const std::unordered_map <std::string, std::string> &headers = {});

    private:
        HttpClientConfig _config;
        std::shared_ptr <spdlog::logger> _logger;

        std::string build_url(const std::string &url) const;

        web::http::http_headers
        merge_headers(const std::unordered_map <std::string, std::string> &additional_headers) const;

        web::http::client::http_client_config create_client_config() const;

        HttpResult convert_response(const web::http::http_response &response);

        static const std::unordered_set <std::string> preflight_methods_;
    };

} // namespace cpprest_client