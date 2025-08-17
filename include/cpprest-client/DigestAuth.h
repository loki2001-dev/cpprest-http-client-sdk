#pragma once

#include "IAuthenticationStrategy.h"
#include <string>
#include <cpprest/http_client.h>

namespace cpprest_client {

    class DigestAuth : public IAuthenticationStrategy {
    public:
        DigestAuth(std::string user, std::string pass, std::string realm = "", std::string nonce = "");

        void apply(web::http::http_request &request) override;

        void setRealm(const std::string &realm);
        void setNonce(const std::string &nonce);

    private:
        std::string _user;
        std::string _pass;
        std::string _realm;
        std::string _nonce;

        static std::string md5_hex(const std::string &input);
    };

} // namespace cpprest_client