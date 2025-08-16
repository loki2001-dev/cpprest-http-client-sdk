#include <gtest/gtest.h>
#include <future>
#include "../include/cpprest-client/HttpClientImpl.h"
#include "../include/cpprest-client/HttpClientCo.h"

using namespace cpprest_client;

// ------------------- 테스트용 기본 설정 -------------------
class HttpClientTestBase : public ::testing::Test {
protected:
    void SetUp() override {
        config_.base_url = "https://jsonplaceholder.typicode.com";
        config_.set_json_content_type();
        config_.add_default_header("User-Agent", "CppRest-Client-Test/1.0");
    }

    Config config_;
};

TEST_F(HttpClientTestBase, GetRequest) {
    HttpClientImpl client(config_);
    auto resp = client.get("/posts/1");

    EXPECT_EQ(resp.status_code, 200);
    EXPECT_TRUE(resp.is_success());
    EXPECT_FALSE(resp.body.empty());

    if (resp.is_json()) {
        EXPECT_TRUE(resp.json_body.has_field("id"));
        EXPECT_TRUE(resp.json_body.has_field("title"));
    }
}

TEST_F(HttpClientTestBase, PostJsonRequest) {
    HttpClientImpl client(config_);
    web::json::value data;
    data["title"] = web::json::value::string("Test Post");
    data["body"] = web::json::value::string("Test Content");
    data["userId"] = web::json::value::number(1);

    auto resp = client.post_json("/posts", data);
    EXPECT_EQ(resp.status_code, 201);
    EXPECT_TRUE(resp.is_success());
    EXPECT_FALSE(resp.body.empty());
}

TEST_F(HttpClientTestBase, PutJsonRequest) {
    HttpClientImpl client(config_);
    web::json::value data;
    data["id"] = web::json::value::number(1);
    data["title"] = web::json::value::string("Updated Post");
    data["body"] = web::json::value::string("Updated Content");
    data["userId"] = web::json::value::number(1);

    auto resp = client.put_json("/posts/1", data);
    EXPECT_EQ(resp.status_code, 200);
    EXPECT_TRUE(resp.is_success());
}

TEST_F(HttpClientTestBase, PatchJsonRequest) {
    HttpClientImpl client(config_);
    web::json::value data;
    data["title"] = web::json::value::string("Patched Title");

    auto resp = client.patch_json("/posts/1", data);
    EXPECT_EQ(resp.status_code, 200);
    EXPECT_TRUE(resp.is_success());
}

TEST_F(HttpClientTestBase, DeleteRequest) {
    HttpClientImpl client(config_);
    auto resp = client.del("/posts/1");
    EXPECT_EQ(resp.status_code, 200);
    EXPECT_TRUE(resp.is_success());
}

TEST_F(HttpClientTestBase, ConcurrentAsyncRequests) {
    HttpClientImpl client(config_);
    const int n = 10;
    std::vector<std::future<HttpResponse>> futures;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 1; i <= n; ++i) {
        futures.push_back(client.get_async("/posts/" + std::to_string(i)));
    }

    for (auto& f : futures) {
        auto resp = f.get();
        EXPECT_EQ(resp.status_code, 200);
        EXPECT_TRUE(resp.is_success());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

TEST_F(HttpClientTestBase, InvalidUrlThrows) {
    Config bad_config;  // base_url 없이 사용
    HttpClientImpl client(bad_config);
    EXPECT_THROW(client.get("/posts/1"), InvalidUrlException);
}

class HttpClientCoTest : public HttpClientTestBase {
protected:
    HttpResult run_task(std::future<HttpResult>&& task) {
        return task.get();
    }

    HttpClientConfig make_co_config() {
        HttpClientConfig co_config;
        co_config.base_url = config_.base_url;
        co_config.default_headers = config_.default_headers;
        co_config.user_agent = "CppRest-Client-Test/1.0";
        co_config.verify_ssl = true;
        co_config.connect_timeout = std::chrono::seconds(5);
        co_config.read_timeout = std::chrono::seconds(10);
        return co_config;
    }
};

TEST_F(HttpClientCoTest, CoroutineGetRequest) {
    HttpClientConfig co_config = make_co_config();
    HttpClientCo client(co_config);

    auto task = client.get_async("/posts/1");
    auto resp = run_task(std::move(task));

    EXPECT_EQ(resp.status_code, 200);
    EXPECT_TRUE(resp.is_success());
    EXPECT_FALSE(resp.body.empty());
}

TEST_F(HttpClientCoTest, CoroutinePostJsonRequest) {
    HttpClientConfig co_config = make_co_config();
    HttpClientCo client(co_config);

    web::json::value data;
    data["title"] = web::json::value::string("Coroutine Test");
    data["body"] = web::json::value::string("Coroutine Content");
    data["userId"] = web::json::value::number(1);

    std::unordered_map<std::string, std::string> headers;
    headers["Content-Type"] = "application/json";

    auto task = client.post_async("/posts", data.serialize(), headers);
    auto resp = run_task(std::move(task));

    EXPECT_EQ(resp.status_code, 201);
    EXPECT_TRUE(resp.is_success());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}