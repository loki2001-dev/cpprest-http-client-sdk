#pragma once

#include <string>
#include <unordered_map>
#include <memory>
#include <future>
#include <cpprest/http_msg.h>
#include <cpprest/json.h>

namespace cpprest_client {

    struct HttpResponse {
        int status_code;
        std::unordered_map <std::string, std::string> headers;
        std::string body;
        web::json::value json_body;

        bool is_success() const {
            return status_code >= 200 && status_code < 300;
        }

        bool is_json() const {
            auto it = headers.find("content-type");
            if (it != headers.end()) {
                return it->second.find("application/json") != std::string::npos;
            }
            return false;
        }
    };

    class IHttpClient {
    public:
        virtual ~IHttpClient() = default;

        // Sync
        virtual HttpResponse get(const std::string &url,
                                 const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse post(const std::string &url,
                                  const std::string &body,
                                  const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse post_json(const std::string &url,
                                       const web::json::value &json,
                                       const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse put(const std::string &url,
                                 const std::string &body,
                                 const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse put_json(const std::string &url,
                                      const web::json::value &json,
                                      const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse patch(const std::string &url,
                                   const std::string &body,
                                   const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse patch_json(const std::string &url,
                                        const web::json::value &json,
                                        const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse del(const std::string &url,
                                 const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse head(const std::string &url,
                                  const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual HttpResponse options(const std::string &url,
                                     const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        // Async
        virtual std::future <HttpResponse> get_async(const std::string &url,
                                                     const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> post_async(const std::string &url,
                                                      const std::string &body,
                                                      const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> post_json_async(const std::string &url,
                                                           const web::json::value &json,
                                                           const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> put_async(const std::string &url,
                                                     const std::string &body,
                                                     const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> put_json_async(const std::string &url,
                                                          const web::json::value &json,
                                                          const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> patch_async(const std::string &url,
                                                       const std::string &body,
                                                       const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> patch_json_async(const std::string &url,
                                                            const web::json::value &json,
                                                            const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> del_async(const std::string &url,
                                                     const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> head_async(const std::string &url,
                                                      const std::unordered_map <std::string, std::string> &headers = {}) = 0;

        virtual std::future <HttpResponse> options_async(const std::string &url,
                                                         const std::unordered_map <std::string, std::string> &headers = {}) = 0;
    };

} // namespace cpprest_client