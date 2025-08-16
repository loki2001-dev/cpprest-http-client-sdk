#pragma once

#include <string>
#include <chrono>
#include <unordered_map>

namespace cpprest_client {

    struct Config {
        std::string base_url;
        std::unordered_map <std::string, std::string> default_headers;
        std::chrono::seconds connect_timeout{30};
        std::chrono::seconds read_timeout{30};
        std::string bearer_token;
        bool verify_ssl{true};
        bool follow_redirects{true};
        int max_redirects{5};
        std::string user_agent{"cpprest-http-client/1.0.0"};

        void set_bearer_token(const std::string &token) {
            bearer_token = token;
            default_headers["Authorization"] = "Bearer " + token;
        }

        void add_default_header(const std::string &name, const std::string &value) {
            default_headers[name] = value;
        }

        void set_json_content_type() {
            default_headers["Content-Type"] = "application/json";
        }
    };

} // namespace cpprest_client