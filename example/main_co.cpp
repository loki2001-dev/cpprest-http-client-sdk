#include <iostream>
#include <vector>
#include <string>
#include <future>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "../include/cpprest-client/HttpClientCo.h"
#include "../include/cpprest-client/Config.h"
#include "../include/cpprest-client/Exceptions.h"

using namespace cpprest_client;

// ------------------- Response 출력 -------------------
void print_response(const HttpResult &response) {
    spdlog::info("Status: {}", response.status_code);
    spdlog::info("Headers:");
    for (const auto &[key, value]: response.headers) {
        spdlog::info("  {}: {}", key, value);
    }
    spdlog::info("Body: {}", response.body);
    spdlog::info("---");
}

// ------------------- 예제 함수 -------------------
void simple_get_example(HttpClientCo &client) {
    try {
        auto resp = client.get_async("/posts/1").get();
        spdlog::info("\n=== simple_get_example ===");
        print_response(resp);
    } catch (const HttpClientException &e) {
        spdlog::error("Error: {}", e.what());
    }
}

void sequential_requests_example(HttpClientCo &client) {
    try {
        auto res1 = client.get_async("/posts/1").get();
        auto res2 = client.get_async("/posts/2").get();
        spdlog::info("\n=== sequential_requests_example ===");
        print_response(res1);
        print_response(res2);
    } catch (const HttpClientException &e) {
        spdlog::error("Error: {}", e.what());
    }
}

void error_handling_example(HttpClientCo &client) {
    try {
        auto resp = client.get_async("/invalid-endpoint").get();
        print_response(resp);
    } catch (const HttpClientException &e) {
        spdlog::warn("Caught exception: {}", e.what());
    }
}

void http_methods_example(HttpClientCo &client) {
    spdlog::info("\n=== http_methods_example ===");
    try {
        web::json::value post_data;
        post_data["title"] = web::json::value::string("Post via std::future");
        post_data["body"] = web::json::value::string("Content for POST");
        post_data["userId"] = web::json::value::number(1);

        auto post_resp = client.post_async("/posts", post_data.serialize()).get();
        print_response(post_resp);

        web::json::value patch_data;
        patch_data["title"] = web::json::value::string("Patched Title");
        auto patch_resp = client.patch_async("/posts/1", patch_data.serialize()).get();
        print_response(patch_resp);

        auto del_resp = client.del_async("/posts/1").get();
        print_response(del_resp);

    } catch (const HttpClientException &e) {
        spdlog::error("Error: {}", e.what());
    }
}

void authentication_example(HttpClientCo &client, HttpClientConfig &config) {
    spdlog::info("\n=== authentication_example ===");
    try {
        config.default_headers["Authorization"] = "Bearer your-secret-token";
        client.update_config(config);

        auto resp = client.get_async("/posts/1").get();
        print_response(resp);
    } catch (const HttpClientException &e) {
        spdlog::error("Error: {}", e.what());
    }
}

// ------------------- 동시 요청 예제 -------------------
void concurrent_requests_example(HttpClientCo &client) {
    spdlog::info("\n=== concurrent_requests_example ===");

    std::vector <std::future<HttpResult>> futures;
    for (int i = 1; i <= 3; ++i) {
        futures.push_back(client.get_async("/posts/" + std::to_string(i)));
    }

    for (auto &f: futures) {
        try {
            auto resp = f.get();
            print_response(resp);
        } catch (const HttpClientException &e) {
            spdlog::error("Concurrent request failed: {}", e.what());
        }
    }
}

// ------------------- 메인 -------------------
int main() {
    // spdlog 초기화 (컬러 콘솔)
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v"); // 시간 + 레벨 + 메시지
    spdlog::set_level(spdlog::level::info);

    try {
        HttpClientConfig config;
        config.base_url = "https://jsonplaceholder.typicode.com";
        config.default_headers["Content-Type"] = "application/json";
        config.default_headers["User-Agent"] = "CppRest-Client-Future/1.0";

        HttpClientCo client(config);

        simple_get_example(client);
        sequential_requests_example(client);
        error_handling_example(client);
        http_methods_example(client);
        authentication_example(client, config);
        concurrent_requests_example(client);

    } catch (const HttpStatusException &e) {
        spdlog::error("HTTP Error: {}", e.what());
        spdlog::error("Status Code: {}", e.status_code());
        spdlog::error("Response Body: {}", e.response_body());
    } catch (const NetworkException &e) {
        spdlog::error("Network Error: {}", e.what());
    } catch (const TimeoutException &e) {
        spdlog::error("Timeout Error: {}", e.what());
    } catch (const JsonException &e) {
        spdlog::error("JSON Error: {}", e.what());
    } catch (const HttpClientException &e) {
        spdlog::error("HTTP Client Error: {}", e.what());
    } catch (const std::exception &e) {
        spdlog::error("Unknown Error: {}", e.what());
    }

    return 0;
}