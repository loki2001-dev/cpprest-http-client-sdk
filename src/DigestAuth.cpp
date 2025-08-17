#include "../include/cpprest-client/DigestAuth.h"
#include "../3rdparty/loki-secure-sdk/src/crypto/md5.h"
#include <sstream>
#include <iomanip>
#include <spdlog/spdlog.h>

using namespace loki;
using namespace loki::crypto;

namespace cpprest_client {

    DigestAuth::DigestAuth(std::string user, std::string pass, std::string realm, std::string nonce)
            : _user(std::move(user)),
              _pass(std::move(pass)),
              _realm(std::move(realm)),
              _nonce(std::move(nonce)) {
    }

    void DigestAuth::apply(web::http::http_request &request) {
        std::string method = utility::conversions::to_utf8string(request.method());
        std::string uri = utility::conversions::to_utf8string(request.request_uri().to_string());

        spdlog::info("DigestAuth::apply called");
        spdlog::info("Request method: {}", method);
        spdlog::info("Request URI: {}", uri);
        spdlog::info("Username: {}, Realm: {}, Nonce: {}", _user, _realm, _nonce);

        // HA1 = MD5(username:realm:password)
        std::string ha1_input = _user + ":" + _realm + ":" + _pass;
        std::string ha1 = md5_hex(ha1_input);
        spdlog::info("HA1 input: {}, HA1: {}", ha1_input, ha1);

        // HA2 = MD5(method:uri)
        std::string ha2_input = method + ":" + uri;
        std::string ha2 = md5_hex(ha2_input);
        spdlog::info("HA2 input: {}, HA2: {}", ha2_input, ha2);

        // response = MD5(HA1:nonce:HA2)
        std::string response_input = ha1 + ":" + _nonce + ":" + ha2;
        std::string response = md5_hex(response_input);
        spdlog::info("Response input: {}, Response: {}", response_input, response);

        std::ostringstream header;
        header << "Digest username=\"" << _user
               << "\", realm=\"" << _realm
               << "\", nonce=\"" << _nonce
               << "\", uri=\"" << uri
               << "\", response=\"" << response
               << "\"";

        spdlog::info("Authorization header: {}", header.str());

        request.headers().add(U("Authorization"), utility::conversions::to_string_t(header.str()));
    }

    void DigestAuth::setRealm(const std::string &realm) {
        _realm = realm;
    }

    void DigestAuth::setNonce(const std::string &nonce) {
        _nonce = nonce;
    }

    std::string DigestAuth::md5_hex(const std::string &input) {
        loki::crypto::MD5 md5(input);
        ByteArray digest = md5.hash(input);

        std::ostringstream oss;
        for (auto byte : digest) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            oss << buf;
        }
        return oss.str();
    }

} // namespace cpprest_client