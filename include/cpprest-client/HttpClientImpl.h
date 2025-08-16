#pragma once

#include "IHttpClient.h"
#include "Config.h"
#include "Exceptions.h"
#include <cpprest/http_client.h>
#include <spdlog/spdlog.h>
#include <memory>
#include <unordered_set>

namespace cpprest_client {

    class HttpClientImpl : public IHttpClient {
    private:
        Config _config;
        std::shared_ptr<spdlog::logger> _logger;

        // CORS preflight
        static const std::unordered_set<std::string> preflight_methods_;

        std::string build_url(const std::string& url) const;

        web::http::http_headers merge_headers(const std::unordered_map<std::string, std::string>& additional_headers) const;

        // HTTP Request
        pplx::task<HttpResponse> execute_request(const std::string& url,
                                                 web::http::method method,
                                                 const std::string& body = "",
                                                 const std::unordered_map<std::string, std::string>& headers = {});

        // CORS preflight
        pplx::task<bool> execute_preflight(const std::string& url,
                                           web::http::method method,
                                           const std::unordered_map<std::string, std::string>& headers = {});

        // HTTP Response
        HttpResponse convert_response(const web::http::http_response& response);

        web::http::client::http_client_config create_client_config() const;

        void handle_exception(const std::exception& e) const;

    public:
        explicit HttpClientImpl(const Config& config = Config{});

        ~HttpClientImpl() override = default;

        void update_config(const Config& config);

        const Config& get_config() const { return config_; }

        // IHttpClient
        HttpResponse get(const std::string& url,
                         const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse post(const std::string& url,
                          const std::string& body,
                          const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse post_json(const std::string& url,
                               const web::json::value& json,
                               const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse put(const std::string& url,
                         const std::string& body,
                         const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse put_json(const std::string& url,
                              const web::json::value& json,
                              const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse patch(const std::string& url,
                           const std::string& body,
                           const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse patch_json(const std::string& url,
                                const web::json::value& json,
                                const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse del(const std::string& url,
                         const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse head(const std::string& url,
                          const std::unordered_map<std::string, std::string>& headers = {}) override;

        HttpResponse options(const std::string& url,
                             const std::unordered_map<std::string, std::string>& headers = {}) override;

        // ASYNC
        std::future<HttpResponse> get_async(const std::string& url,
                                            const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> post_async(const std::string& url,
                                             const std::string& body,
                                             const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> post_json_async(const std::string& url,
                                                  const web::json::value& json,
                                                  const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> put_async(const std::string& url,
                                            const std::string& body,
                                            const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> put_json_async(const std::string& url,
                                                 const web::json::value& json,
                                                 const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> patch_async(const std::string& url,
                                              const std::string& body,
                                              const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> patch_json_async(const std::string& url,
                                                   const web::json::value& json,
                                                   const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> del_async(const std::string& url,
                                            const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> head_async(const std::string& url,
                                             const std::unordered_map<std::string, std::string>& headers = {}) override;

        std::future<HttpResponse> options_async(const std::string& url,
                                                const std::unordered_map<std::string, std::string>& headers = {}) override;
    };

} // namespace cpprest_client