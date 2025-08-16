#include <iostream>
#include <thread>
#include <chrono>
#include "../include/cpprest-client/HttpClientImpl.h"
#include "../include/cpprest-client/Config.h"
#include "../include/cpprest-client/Exceptions.h"
#include <spdlog/spdlog.h>

using namespace cpprest_client;

void print_response(const HttpResponse &response) {
    spdlog::info("Status: {}", response.status_code);
    spdlog::info("Headers:");
    for (const auto &[key, value]: response.headers) {
        spdlog::info("  {}: {}", key, value);
    }
    spdlog::info("Body: {}", response.body);
    spdlog::info("---");
}

int main() {
    try {
        spdlog::info("=== HTTP Client Example ===");

        // 기본 설정으로 클라이언트 생성
        Config config;
        config.base_url = "https://jsonplaceholder.typicode.com";
        config.set_json_content_type();
        config.add_default_header("User-Agent", "CppRest-Client-Example/1.0");

        HttpClientImpl client(config);

        // 1. GET 요청
        spdlog::info("\n1. GET /posts/1");
        auto get_response = client.get("/posts/1");
        print_response(get_response);

        // 2. POST 요청 (JSON)
        spdlog::info("\n2. POST /posts (JSON)");
        web::json::value post_data;
        post_data["title"] = web::json::value::string("My New Post");
        post_data["body"] = web::json::value::string("This is the content of my post");
        post_data["userId"] = web::json::value::number(1);

        auto post_response = client.post_json("/posts", post_data);
        print_response(post_response);

        // 3. PUT 요청
        spdlog::info("\n3. PUT /posts/1");
        web::json::value put_data;
        put_data["id"] = web::json::value::number(1);
        put_data["title"] = web::json::value::string("Updated Post");
        put_data["body"] = web::json::value::string("Updated content");
        put_data["userId"] = web::json::value::number(1);

        auto put_response = client.put_json("/posts/1", put_data);
        print_response(put_response);

        // 4. PATCH 요청
        spdlog::info("\n4. PATCH /posts/1");
        web::json::value patch_data;
        patch_data["title"] = web::json::value::string("Patched Title");

        auto patch_response = client.patch_json("/posts/1", patch_data);
        print_response(patch_response);

        // 5. DELETE 요청
        spdlog::info("\n5. DELETE /posts/1");
        auto delete_response = client.del("/posts/1");
        print_response(delete_response);

        // 6. HEAD 요청
        spdlog::info("\n6. HEAD /posts/1");
        auto head_response = client.head("/posts/1");
        print_response(head_response);

        // 7. OPTIONS 요청
        spdlog::info("\n7. OPTIONS /posts");
        auto options_response = client.options("/posts");
        print_response(options_response);

        // 8. Bearer Token 설정 예제
        spdlog::info("\n8. Bearer Token 예제");
        config.set_bearer_token("your-secret-token");
        client.update_config(config);

        auto auth_response = client.get("/posts/1");
        print_response(auth_response);

        // 9. 비동기 요청 예제
        spdlog::info("\n9. 비동기 GET 요청");
        auto future_response = client.get_async("/posts/2");

        spdlog::info("다른 작업 수행 중...");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        auto async_response = future_response.get();
        print_response(async_response);

        // 10. 여러 비동기 요청 동시 실행
        spdlog::info("\n10. 여러 비동기 요청 동시 실행");
        std::vector <std::future<HttpResponse>> futures;

        for (int i = 1; i <= 3; ++i) {
            futures.push_back(client.get_async("/posts/" + std::to_string(i)));
        }

        for (size_t i = 0; i < futures.size(); ++i) {
            spdlog::info("Response {}", i + 1);
            print_response(futures[i].get());
        }

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