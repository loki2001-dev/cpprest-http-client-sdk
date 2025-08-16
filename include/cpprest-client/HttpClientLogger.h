#include <spdlog/sinks/stdout_color_sinks.h>

class HttpClientLogger {
public:
    static std::shared_ptr <spdlog::logger> get_logger(const std::string &name = "http_client") {
        static std::shared_ptr <spdlog::logger> http_logger = nullptr;

        if (!http_logger) {
            auto logger = spdlog::get(name);
            if (!logger) {
                logger = spdlog::stdout_color_mt(name);
                logger->set_level(spdlog::level::info);
            }
            http_logger = logger;
        }

        return http_logger;
    }
};