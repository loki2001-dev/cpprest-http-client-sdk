#pragma once

#include "IAuthenticationStrategy.h"
#include "Config.h"

namespace cpprest_client {

    class OAuth2Auth : public IAuthenticationStrategy {
    public:
        explicit OAuth2Auth(Config &config)
                : _config(config) {

        }

        void apply(web::http::http_request &request) override {
            _config.refresh_access_token_if_needed();
            if (!_config.access_token.empty()) {
                request.headers().add(U("Authorization"),
                                      U("Bearer ") + utility::conversions::to_string_t(_config.access_token));
            }
        }

    private:
        Config &_config;
    };

} // namespace cpprest_client