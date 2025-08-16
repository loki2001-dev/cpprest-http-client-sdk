#pragma once

#include <string>
#include <unordered_map>
#include <chrono>

namespace cpprest_client {

    struct Config {
        // Basic settings
        std::string base_url;
        std::string user_agent = "CppRest-Client/1.0";
        std::unordered_map<std::string, std::string> default_headers;

        // Timeout settings
        std::chrono::milliseconds connect_timeout{10000};  // 10 seconds
        std::chrono::milliseconds read_timeout{30000};     // 30 seconds

        // SSL settings
        bool verify_ssl = true;

        // HTTP/2 and Connection Pool settings
        bool enable_http2 = true;
        bool enable_connection_pool = true;
        bool enable_keep_alive = true;
        size_t max_connections_per_host = 6;
        std::chrono::seconds connection_idle_timeout{30};
        size_t max_concurrent_streams = 100;  // HTTP/2 multiplexing streams

        // Utility methods
        void add_default_header(const std::string& key, const std::string& value) {
            default_headers[key] = value;
        }

        void remove_default_header(const std::string& key) {
            default_headers.erase(key);
        }

        void set_json_content_type() {
            add_default_header("Content-Type", "application/json");
            add_default_header("Accept", "application/json");
        }

        void set_bearer_token(const std::string& token) {
            add_default_header("Authorization", "Bearer " + token);
        }

        void remove_bearer_token() {
            remove_default_header("Authorization");
        }

        void set_basic_auth(const std::string& username, const std::string& password) {
            // Simple base64 encoding would be needed here
            // For now, just set the header format
            std::string credentials = username + ":" + password;
            // Note: In real implementation, you'd want to base64 encode this
            add_default_header("Authorization", "Basic " + credentials);
        }

        void set_custom_user_agent(const std::string& agent) {
            user_agent = agent;
            add_default_header("User-Agent", agent);
        }

        // HTTP/2 specific settings
        void enable_http2_features() {
            enable_http2 = true;
            enable_connection_pool = true;
            enable_keep_alive = true;
            max_concurrent_streams = 100;
        }

        void disable_http2_features() {
            enable_http2 = false;
            max_concurrent_streams = 1;
        }

        // Connection pool specific settings
        void configure_connection_pool(size_t max_connections, std::chrono::seconds idle_timeout) {
            enable_connection_pool = true;
            max_connections_per_host = max_connections;
            connection_idle_timeout = idle_timeout;
        }

        void disable_connection_pool() {
            enable_connection_pool = false;
        }

        // Performance tuning presets
        void set_high_performance_preset() {
            enable_http2 = true;
            enable_connection_pool = true;
            enable_keep_alive = true;
            max_connections_per_host = 10;
            connection_idle_timeout = std::chrono::seconds(60);
            max_concurrent_streams = 200;
            connect_timeout = std::chrono::milliseconds(5000);
            read_timeout = std::chrono::milliseconds(15000);
        }

        void set_conservative_preset() {
            enable_http2 = false;
            enable_connection_pool = false;
            enable_keep_alive = false;
            max_connections_per_host = 2;
            connection_idle_timeout = std::chrono::seconds(10);
            max_concurrent_streams = 1;
            connect_timeout = std::chrono::milliseconds(15000);
            read_timeout = std::chrono::milliseconds(60000);
        }

        // Debug/logging helpers
        std::string to_string() const {
            std::string result = "Config {\n";
            result += "  base_url: " + base_url + "\n";
            result += "  user_agent: " + user_agent + "\n";
            result += "  enable_http2: " + std::string(enable_http2 ? "true" : "false") + "\n";
            result += "  enable_connection_pool: " + std::string(enable_connection_pool ? "true" : "false") + "\n";
            result += "  enable_keep_alive: " + std::string(enable_keep_alive ? "true" : "false") + "\n";
            result += "  max_connections_per_host: " + std::to_string(max_connections_per_host) + "\n";
            result += "  connection_idle_timeout: " + std::to_string(connection_idle_timeout.count()) + "s\n";
            result += "  max_concurrent_streams: " + std::to_string(max_concurrent_streams) + "\n";
            result += "  connect_timeout: " + std::to_string(connect_timeout.count()) + "ms\n";
            result += "  read_timeout: " + std::to_string(read_timeout.count()) + "ms\n";
            result += "  verify_ssl: " + std::string(verify_ssl ? "true" : "false") + "\n";
            result += "  default_headers: {\n";
            for (const auto& [key, value] : default_headers) {
                result += "    " + key + ": " + value + "\n";
            }
            result += "  }\n";
            result += "}";
            return result;
        }
    };

} // namespace cpprest_client