#pragma once

#include "IAuthenticationStrategy.h"

namespace cpprest_client {

    class BasicAuth : public IAuthenticationStrategy {
    public:
        BasicAuth(std::string user, std::string pass)
                : _user(std::move(user)),
                  _pass(std::move(pass)) {

        }

        void apply(web::http::http_request &request) override {
            auto credentials = _user + ":" + _pass;
/*            auto encoded = utility::conversions::to_base64(utility::conversions::to_utf8string(credentials));
            request.headers().add(U("Authorization"), U("Basic ") + utility::conversions::to_string_t(encoded));*/
        }

    private:
        std::string _user;
        std::string _pass;
    };

} // namespace cpprest_client