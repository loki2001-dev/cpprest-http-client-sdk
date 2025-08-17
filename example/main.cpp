#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <future>
#include "../include/cpprest-client/HttpClientImpl.h"
#include "../include/cpprest-client/Config.h"
#include "../include/cpprest-client/Exceptions.h"
#include "../include/cpprest-client/BearerAuth.h"
#include "../include/cpprest-client/BasicAuth.h"
#include "../include/cpprest-client/DigestAuth.h"
#include "../include/cpprest-client/OAuth2Auth.h"
#include <spdlog/spdlog.h>
#include <cpprest/http_msg.h>

using namespace cpprest_client;

void print_response_summary(const HttpResponse &response, int request_num = 0) {
    if (request_num > 0) {
        spdlog::info("[RESPONSE] Request #{}: Status {} | Body size: {} bytes",
                     request_num, response.status_code, response.body.length());
    } else {
        spdlog::info("[RESPONSE] Status Code: {}", response.status_code);

        // Only show a few important headers
        auto content_type = response.headers.find("content-type");
        if (content_type != response.headers.end()) {
            spdlog::info("[RESPONSE] Content-Type: {}", content_type->second);
        }

        // Show authorization header if present (for testing)
        auto auth_header = response.headers.find("authorization");
        if (auth_header != response.headers.end()) {
            spdlog::info("[RESPONSE] Authorization header was processed");
        }

        // Truncate body for readability
        std::string body = response.body;
        if (body.length() > 200) {
            body = body.substr(0, 200) + "... (truncated)";
        }
        spdlog::info("[RESPONSE] Body: {}", body);
        spdlog::info("[RESPONSE] ---");
    }
}

void demo_basic_requests(HttpClientImpl &client) {
    spdlog::info("\n[DEMO] === BASIC HTTP METHODS DEMONSTRATION ===");

    try {
        // 1. GET Request
        spdlog::info("\n[TEST] 1. Executing GET /posts/1");
        auto get_response = client.get("/posts/1");
        print_response_summary(get_response);

        // 2. POST Request (JSON)
        spdlog::info("\n[TEST] 2. Executing POST /posts with JSON payload");
        web::json::value post_data;
        post_data["title"] = web::json::value::string("My New Post");
        post_data["body"] = web::json::value::string("This is the content of my post");
        post_data["userId"] = web::json::value::number(1);

        auto post_response = client.post_json("/posts", post_data);
        print_response_summary(post_response);

        // 3. PUT Request
        spdlog::info("\n[TEST] 3. Executing PUT /posts/1");
        web::json::value put_data;
        put_data["id"] = web::json::value::number(1);
        put_data["title"] = web::json::value::string("Updated Post");
        put_data["body"] = web::json::value::string("Updated content");
        put_data["userId"] = web::json::value::number(1);

        auto put_response = client.put_json("/posts/1", put_data);
        print_response_summary(put_response);

        // 4. PATCH Request
        spdlog::info("\n[TEST] 4. Executing PATCH /posts/1");
        web::json::value patch_data;
        patch_data["title"] = web::json::value::string("Patched Title");

        auto patch_response = client.patch_json("/posts/1", patch_data);
        print_response_summary(patch_response);

        // 5. DELETE Request
        spdlog::info("\n[TEST] 5. Executing DELETE /posts/1");
        auto delete_response = client.del("/posts/1");
        print_response_summary(delete_response);

        // 6. HEAD Request
        spdlog::info("\n[TEST] 6. Executing HEAD /posts/1");
        auto head_response = client.head("/posts/1");
        spdlog::info("[RESPONSE] HEAD Status: {} | Headers count: {}",
                     head_response.status_code, head_response.headers.size());

        // 7. OPTIONS Request
        spdlog::info("\n[TEST] 7. Executing OPTIONS /posts");
        auto options_response = client.options("/posts");
        print_response_summary(options_response);

        spdlog::info("[DEMO] Basic HTTP methods demonstration completed successfully");

    } catch (const std::exception &e) {
        spdlog::error("[ERROR] Basic requests demo failed: {}", e.what());
    }
}

void demo_async_requests(HttpClientImpl &client) {
    spdlog::info("\n[DEMO] === ASYNCHRONOUS REQUESTS DEMONSTRATION ===");

    try {
        // Single Async Request
        spdlog::info("\n[TEST] Executing single asynchronous GET request");
        auto future_response = client.get_async("/posts/2");

        spdlog::info("[INFO] Performing other tasks while request is in progress...");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        spdlog::info("[INFO] Waiting for async response...");
        auto async_response = future_response.get();
        print_response_summary(async_response);

        // Multiple Concurrent Async Requests (Connection Pool Test)
        spdlog::info("\n[TEST] Executing 5 concurrent async requests");
        std::vector <std::future<HttpResponse>> futures;

        auto start_time = std::chrono::high_resolution_clock::now();

        for (int i = 1; i <= 5; ++i) {
            futures.push_back(client.get_async("/posts/" + std::to_string(i)));
        }

        spdlog::info("[INFO] {} concurrent requests initiated", futures.size());

        for (size_t i = 0; i < futures.size(); ++i) {
            auto response = futures[i].get();
            print_response_summary(response, i + 1);
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        spdlog::info("[PERF] 5 concurrent requests completed in: {}ms", duration.count());

        spdlog::info("[DEMO] Asynchronous requests demonstration completed successfully");

    } catch (const std::exception &e) {
        spdlog::error("[ERROR] Async requests demo failed: {}", e.what());
    }
}

void demo_connection_pool_performance(HttpClientImpl &client_with_pool, HttpClientImpl &client_without_pool) {
    spdlog::info("\n[DEMO] ===== CONNECTION POOL PERFORMANCE COMPARISON =====");

    const int num_requests = 500;

    try {
        ////////////////////////////////////////
        // Test: with Connection Pool
        ////////////////////////////////////////
        spdlog::info("\n[TEST] Performance Test 1: Connection Pool ENABLED");
        auto start_with_pool = std::chrono::high_resolution_clock::now();

        std::vector <std::future<HttpResponse>> futures_with_pool;
        for (int i = 1; i <= num_requests; ++i) {
            futures_with_pool.push_back(client_with_pool.get_async("/posts/" + std::to_string(i % 5 + 1)));
        }

        spdlog::info("[INFO] {} requests initiated with connection pool", num_requests);

        int completed_with_pool = 0;
        for (auto &future: futures_with_pool) {
            future.get();
            completed_with_pool++;
            if (completed_with_pool % 5 == 0) {
                spdlog::info("[PROGRESS] Completed {}/{} requests (with pool)", completed_with_pool, num_requests);
            }
        }

        auto end_with_pool = std::chrono::high_resolution_clock::now();
        auto duration_with_pool = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_with_pool - start_with_pool);

        ////////////////////////////////////////
        // Test without Connection Pool
        ////////////////////////////////////////
        spdlog::info("\n[TEST] Performance Test 2: Connection Pool DISABLED");
        auto start_without_pool = std::chrono::high_resolution_clock::now();

        std::vector <std::future<HttpResponse>> futures_without_pool;
        for (int i = 1; i <= num_requests; ++i) {
            futures_without_pool.push_back(client_without_pool.get_async("/posts/" + std::to_string(i % 5 + 1)));
        }

        spdlog::info("[INFO] {} requests initiated without connection pool", num_requests);

        int completed_without_pool = 0;
        for (auto &future: futures_without_pool) {
            future.get();
            completed_without_pool++;
            if (completed_without_pool % 5 == 0) {
                spdlog::info("[PROGRESS] Completed {}/{} requests (without pool)", completed_without_pool,
                             num_requests);
            }
        }

        auto end_without_pool = std::chrono::high_resolution_clock::now();
        auto duration_without_pool = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_without_pool - start_without_pool);

        ////////////////////////////////////////
        // Performance Comparison Results
        ////////////////////////////////////////
        spdlog::info("\n[RESULTS] === PERFORMANCE COMPARISON RESULTS ===");
        spdlog::info("[PERF] With Connection Pool:    {}ms", duration_with_pool.count());
        spdlog::info("[PERF] Without Connection Pool: {}ms", duration_without_pool.count());

        if (duration_with_pool < duration_without_pool) {
            double improvement =
                    ((double) (duration_without_pool - duration_with_pool).count() / duration_without_pool.count()) *
                    100;
            spdlog::info("[PERF] Performance improvement: {:.1f}% faster with connection pool", improvement);
        } else if (duration_without_pool < duration_with_pool) {
            double degradation =
                    ((double) (duration_with_pool - duration_without_pool).count() / duration_with_pool.count()) * 100;
            spdlog::warn("[PERF] Connection pool was {:.1f}% slower (may indicate overhead for small request count)",
                         degradation);
        } else {
            spdlog::info("[PERF] No significant performance difference observed");
        }
        spdlog::info("[DEMO] Connection pool performance comparison completed");
    } catch (const std::exception &e) {
        spdlog::error("[ERROR] Performance comparison failed: {}", e.what());
    }
}

void demo_http2_features(HttpClientImpl &client) {
    spdlog::info("\n[DEMO] === HTTP/2 FEATURES DEMONSTRATION ===");

    try {
        // HTTP/2 Multiplexing Test with Concurrent Requests
        spdlog::info("\n[TEST] HTTP/2 Multiplexing Test - Concurrent Request Processing");

        std::vector <std::future<HttpResponse>> futures;
        auto start_time = std::chrono::high_resolution_clock::now();

        // Send multiple requests to same host simultaneously (HTTP/2 Multiplexing effect)
        for (int i = 1; i <= 8; ++i) {
            futures.push_back(client.get_async("/posts/" + std::to_string(i)));
        }

        spdlog::info("[INFO] 8 concurrent requests sent (attempting HTTP/2 multiplexing)");

        int completed = 0;
        for (auto &future: futures) {
            auto response = future.get();
            completed++;
            if (completed % 2 == 0 || completed == 1 || completed == 8) {
                spdlog::info("[PROGRESS] Request {} of 8 completed (Status: {})", completed, response.status_code);
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        spdlog::info("[PERF] 8 concurrent requests processed in: {}ms", duration.count());

        spdlog::info("[DEMO] HTTP/2 features demonstration completed successfully");

    } catch (const std::exception &e) {
        spdlog::error("[ERROR] HTTP/2 demo failed: {}", e.what());
    }
}

void demo_authentication_strategies(HttpClientImpl &client) {
    spdlog::info("\n[DEMO] === AUTHENTICATION STRATEGIES DEMONSTRATION ===");

    try {
        // 1. Bearer Token Authentication
        spdlog::info("\n[TEST] 1. Bearer Token Authentication");
        auto bearer_auth = std::make_shared<BearerAuth>("secret-token-12345");
        client.setAuthentication(bearer_auth);

        spdlog::info("[AUTH] Setting Bearer Token authentication");
        auto bearer_response = client.get("/posts/1");
        print_response_summary(bearer_response);

        // 2. Basic Authentication
        spdlog::info("\n[TEST] 2. Basic Authentication");
        auto basic_auth = std::make_shared<BasicAuth>("username", "password");
        client.setAuthentication(basic_auth);
        auto basic_response = client.get("/posts/2");
        print_response_summary(basic_response);

        // 3. Digest Authentication
        spdlog::info("\n[TEST] 3. Digest Authentication");
        auto digest_auth = std::make_shared<DigestAuth>("user", "pass", "realm", "nonce");
        client.setAuthentication(digest_auth);
        auto digest_response = client.get("/posts/3");
        print_response_summary(digest_response);

        // 4. OAuth2 Authentication
        spdlog::info("\n[TEST] 4. OAuth2 Authentication");
        Config config;
        config.set_json_content_type();
        config.set_bearer_token("initial-access-token", std::chrono::seconds(10));
        config.set_refresh_token("dummy-refresh-token");
        config.set_refresh_callback([](const std::string& refresh_token) -> std::string {
            spdlog::info("Refreshing access token using refresh token: {}", refresh_token);
            return "new-access-token";
        });
        auto oauth2_auth = std::make_shared<OAuth2Auth>(config);
        client.setAuthentication(oauth2_auth);
        auto oauth2_response = client.get("/posts/4");
        print_response_summary(oauth2_response);

        // 5. Clear Authentication
        spdlog::info("\n[TEST] 5. Clearing Authentication");
        client.setAuthentication(nullptr);

        spdlog::info("[AUTH] Cleared authentication");
        auto no_auth_response = client.get("/posts/3");
        print_response_summary(no_auth_response);

        spdlog::info("[DEMO] Authentication strategies demonstration completed successfully");

    } catch (const std::exception &e) {
        spdlog::error("[ERROR] Authentication demo failed: {}", e.what());
    }
}

void demo_custom_headers_and_config(HttpClientImpl &client) {
    spdlog::info("\n[DEMO] === CUSTOM HEADERS AND CONFIGURATION ===");

    try {
        // Test with custom headers per request
        spdlog::info("\n[TEST] Request with custom headers");
        std::unordered_map <std::string, std::string> custom_headers = {
                {"X-Custom-Header", "CustomValue123"},
                {"X-Request-ID",    "req-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count())},
                {"Accept-Language", "en-US,en;q=0.9"}
        };

        auto response_with_headers = client.get("/posts/1", custom_headers);
        print_response_summary(response_with_headers);

        // Test configuration update
        spdlog::info("\n[TEST] Dynamic configuration update");
        Config new_config = client.get_config();
        new_config.add_default_header("X-Client-Version", "2.0.0");
        new_config.add_default_header("X-Environment", "demo");
        client.update_config(new_config);

        auto response_with_updated_config = client.get("/posts/2");
        print_response_summary(response_with_updated_config);

        spdlog::info("[DEMO] Custom headers and configuration demonstration completed");

    } catch (const std::exception &e) {
        spdlog::error("[ERROR] Custom headers demo failed: {}", e.what());
    }
}

int main() {
    try {
        // Set log level to info to reduce noise, change to debug for detailed logging
        spdlog::set_level(spdlog::level::info);
        spdlog::info("[MAIN] === Enhanced HTTP Client Example with HTTP/2 & Connection Pool & Authentication ===");

        Config config_with_pool;

        // 1. Configuration with HTTP/2 and Connection Pool enabled
        {
            spdlog::info("[CONFIG] Initializing HTTP client with enhanced features");
            config_with_pool.base_url = "https://jsonplaceholder.typicode.com";
            config_with_pool.add_default_header("Content-Type", "application/json");
            config_with_pool.add_default_header("User-Agent", "CppRest-Client-Enhanced/2.0");

            // Enable (HTTP/2, Connection Pool)
            config_with_pool.enable_http2 = true;
            config_with_pool.enable_connection_pool = true;
            config_with_pool.enable_keep_alive = true;
            config_with_pool.max_connections_per_host = 6;
            config_with_pool.connection_idle_timeout = std::chrono::seconds(30);
            config_with_pool.max_concurrent_streams = 100;

            // Timeout settings
            config_with_pool.connect_timeout = std::chrono::seconds(10);
            config_with_pool.read_timeout = std::chrono::seconds(30);
        }

        HttpClientImpl client_with_pool(config_with_pool);

        // 2. Configuration without Connection Pool (for performance comparison)
        Config config_without_pool = config_with_pool;
        config_without_pool.enable_connection_pool = false;
        HttpClientImpl client_without_pool(config_without_pool);

        // Execute Demonstrations
        spdlog::info("[MAIN] Starting comprehensive demonstration sequence");

        demo_basic_requests(client_with_pool);
        demo_async_requests(client_with_pool);
        demo_authentication_strategies(client_with_pool);
        demo_custom_headers_and_config(client_with_pool);
        demo_http2_features(client_with_pool);
        demo_connection_pool_performance(client_with_pool, client_without_pool);

        // Display Final Configuration Summary
        spdlog::info("\n\n[CONFIG] === FINAL CONFIGURATION SUMMARY ===");
        const auto &current_config = client_with_pool.get_config();
        spdlog::info("[CONFIG] Base URL: {}", current_config.base_url);
        spdlog::info("[CONFIG] HTTP/2: {}", current_config.enable_http2 ? "ENABLED" : "DISABLED");
        spdlog::info("[CONFIG] Connection Pool: {}", current_config.enable_connection_pool ? "ENABLED" : "DISABLED");
        spdlog::info("[CONFIG] Keep-Alive: {}", current_config.enable_keep_alive ? "ENABLED" : "DISABLED");
        spdlog::info("[CONFIG] Max Connections/Host: {}", current_config.max_connections_per_host);
        spdlog::info("[CONFIG] Max Concurrent Streams: {}", current_config.max_concurrent_streams);
        spdlog::info("[CONFIG] Connect Timeout: {}s", current_config.connect_timeout.count());
        spdlog::info("[CONFIG] Read Timeout: {}s", current_config.read_timeout.count());

        spdlog::info("\n[CONFIG] Default Headers:");
        for (const auto &[key, value]: current_config.default_headers) {
            spdlog::info("[CONFIG]   {}: {}", key, value);
        }

        spdlog::info("\n[MAIN] === ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY ===");

    } catch (const HttpStatusException &e) {
        spdlog::error("[HTTP_ERROR] HTTP Status Error: {} (Code: {})", e.what(), e.status_code());
        if (!e.response_body().empty()) {
            spdlog::error("[HTTP_ERROR] Response: {}", e.response_body().substr(0, 200));
        }
    } catch (const NetworkException &e) {
        spdlog::error("[NETWORK_ERROR] Network connectivity issue: {}", e.what());
    } catch (const TimeoutException &e) {
        spdlog::error("[TIMEOUT_ERROR] Request timeout: {}", e.what());
    } catch (const JsonException &e) {
        spdlog::error("[JSON_ERROR] JSON processing error: {}", e.what());
    } catch (const HttpClientException &e) {
        spdlog::error("[CLIENT_ERROR] HTTP client error: {}", e.what());
    } catch (const std::exception &e) {
        spdlog::error("[UNKNOWN_ERROR] Unexpected error: {}", e.what());
    }

    return 0;
}