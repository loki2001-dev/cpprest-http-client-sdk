#pragma once

#include "IAuthenticationStrategy.h"
#include <string>

namespace cpprest_client {

    class BearerAuth : public IAuthenticationStrategy {
    public:
        explicit BearerAuth(std::string token)
                : _token(std::move(token)) {

        }

        void apply(web::http::http_request &request) override {
            request.headers().add(U("Authorization"), U("Bearer ") + utility::conversions::to_string_t(_token));
        }

    private:
        std::string _token;
    };

} // namespace cpprest_client