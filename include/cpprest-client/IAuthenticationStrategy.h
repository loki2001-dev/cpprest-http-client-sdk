#pragma once

#include <cpprest/http_client.h>

namespace cpprest_client {

    class IAuthenticationStrategy {
    public:
        virtual ~IAuthenticationStrategy() = default;

        virtual void apply(web::http::http_request &request) = 0;
    };

} // namespace cpprest_client\