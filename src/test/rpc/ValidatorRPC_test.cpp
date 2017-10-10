//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012-2016 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <BeastConfig.h>
#include <ripple/app/misc/ValidatorSite.h>
#include <ripple/beast/unit_test.h>
#include <ripple/core/ConfigSections.h>
#include <ripple/json/json_value.h>
#include <ripple/protocol/JsonFields.h>
#include <ripple/protocol/Sign.h>
#include <beast/core/detail/base64.hpp>
#include <test/jtx.h>
#include <test/jtx/TrustedPublisherServer.h>

#include <boost/format.hpp>
#include <set>

namespace ripple {

namespace test {

class ValidatorRPC_test : public beast::unit_test::suite
{
    static PublicKey
    randomNode()
    {
        return derivePublicKey(KeyType::secp256k1, randomSecretKey());
    }

    std::string
    makeManifestString(
        PublicKey const& pk,
        SecretKey const& sk,
        PublicKey const& spk,
        SecretKey const& ssk,
        int seq)
    {
        STObject st(sfGeneric);
        st[sfSequence] = seq;
        st[sfPublicKey] = pk;
        st[sfSigningPubKey] = spk;

        sign(st, HashPrefix::manifest, *publicKeyType(spk), ssk);
        sign(
            st,
            HashPrefix::manifest,
            *publicKeyType(pk),
            sk,
            sfMasterSignature);

        Serializer s;
        st.add(s);

        return beast::detail::base64_encode(
            std::string(static_cast<char const*>(s.data()), s.size()));
    }

public:
    void
    testPriviledges()
    {
        using namespace test::jtx;

        struct Cmd
        {
            std::string rpcCommand;
            bool adminOnly;
        };

        for (bool const isAdmin : {true, false})
        {
            for (Cmd const cmd : {Cmd{"validator_lists", true},
                                  Cmd{"validator_sites", true},
                                  Cmd{"server_info", false},
                                  Cmd{"server_state", false}})
            {
                Env env{*this, isAdmin ? envconfig() : envconfig(no_admin)};
                auto const jrr = env.rpc(cmd.rpcCommand)[jss::result];
                if (isAdmin || !cmd.adminOnly)
                {
                    BEAST_EXPECT(!jrr.isMember(jss::error));
                    BEAST_EXPECT(jrr[jss::status] == "success");
                }
                else
                {
                    // The current HTTP/S ServerHandler returns an HTTP 403
                    // error code here rather than a noPermission JSON error.
                    // The JSONRPCClient just eats that error and returns an
                    // null result.
                    BEAST_EXPECT(jrr.isNull());
                }
            }
        }
    }

    void
    testStaticUNL()
    {
        using namespace test::jtx;

        std::set<std::string> const keys = {
            "n949f75evCHwgyP4fPVgaHqNHxUVN15PsJEZ3B3HnXPcPjcZAoy7",
            "n9MD5h24qrQqiyBC8aeqqCWvpiBiYQ3jxSr91uiDvmrkyHRdYLUj"};
        Env env{
            *this,
            envconfig([&keys](std::unique_ptr<Config> cfg) {
                for (auto const& key : keys)
                    cfg->section(SECTION_VALIDATORS).append(key);
                return cfg;
            }),
        };

        // Server info reports maximum expiration since not dynamic
        {
            auto const jrr = env.rpc("server_info")[jss::result];
            BEAST_EXPECT(
                jrr[jss::info][jss::validator_list_expires] ==
                to_string(NetClock::time_point::max()));
        }
        {
            auto const jrr = env.rpc("server_state")[jss::result];
            BEAST_EXPECT(
                jrr[jss::state][jss::validator_list_expires].asUInt() ==
                NetClock::time_point::max().time_since_epoch().count());
        }
        // All our keys are in the response
        {
            auto const jrr = env.rpc("validator_lists")[jss::result];
            BEAST_EXPECT(
                jrr[jss::validator_list_expires] ==
                to_string(NetClock::time_point::max()));
            BEAST_EXPECT(jrr[jss::validation_quorum].asUInt() == keys.size());
            BEAST_EXPECT(jrr[jss::validator_keys].size() == keys.size());
            std::set<std::string> foundKeys;
            for (auto const& jKeys : jrr[jss::validator_keys])
            {
                foundKeys.insert(jKeys[jss::pubkey_validator].asString());
            }
            BEAST_EXPECT(foundKeys == keys);
        }
        // No validator sites configured
        {
            auto const jrr = env.rpc("validator_sites")[jss::result];
            BEAST_EXPECT(jrr[jss::validator_sites].size() == 0);
        }
    }

    void
    testDynamicUNL()
    {
        using namespace test::jtx;
        using endpoint_type = boost::asio::ip::tcp::endpoint;
        using address_type = boost::asio::ip::address;

        auto toStr = [](PublicKey const& publicKey) {
            return toBase58(TokenType::TOKEN_NODE_PUBLIC, publicKey);
        };

        // Publisher manifest/signing keys
        auto const publisherSecret = randomSecretKey();
        auto const publisherPublic =
            derivePublicKey(KeyType::ed25519, publisherSecret);
        auto const publisherSigningKeys = randomKeyPair(KeyType::secp256k1);
        auto const manifest = makeManifestString(
            publisherPublic,
            publisherSecret,
            publisherSigningKeys.first,
            publisherSigningKeys.second,
            1);

        // Validator keys that will be in the published list
        std::vector<PublicKey> keys = {randomNode(), randomNode()};
        std::set<std::string> expectedKeys;
        for (auto const& key : keys)
            expectedKeys.insert(toStr(key));

        // Publisher site information
        std::uint16_t constexpr port = 7475;
        endpoint_type ep{address_type::from_string("127.0.0.1"), port};
        std::string siteURI =
            "http://127.0.0.1:" + std::to_string(port) + "/validators";

        //----------------------------------------------------------------------
        // Publisher list site unavailable
        {
            Env env{
                *this,
                envconfig([&](std::unique_ptr<Config> cfg) {
                    cfg->section(SECTION_VALIDATOR_LIST_SITES).append(siteURI);
                    cfg->section(SECTION_VALIDATOR_LIST_KEYS)
                        .append(strHex(publisherPublic));
                    return cfg;
                }),
            };
            {
                auto const jrr = env.rpc("server_info")[jss::result];
                BEAST_EXPECT(
                    jrr[jss::info][jss::validator_list_expires] == "unknown");
            }
            {
                auto const jrr = env.rpc("server_state")[jss::result];
                BEAST_EXPECT(
                    jrr[jss::state][jss::validator_list_expires].asInt() == 0);
            }
            {
                auto const jrr = env.rpc("validator_lists")[jss::result];
                BEAST_EXPECT(jrr[jss::validation_quorum].asUInt() ==
                    std::numeric_limits<std::uint32_t>::max());
                BEAST_EXPECT(jrr[jss::validator_keys].size() == 0);
                BEAST_EXPECT(jrr[jss::validator_list_expires] == "unknown");

                if (BEAST_EXPECT(jrr[jss::publisher_lists].size() == 1))
                {
                    auto jp = jrr[jss::publisher_lists][0u];
                    BEAST_EXPECT(jp[jss::available] == false);
                    BEAST_EXPECT(jp[jss::list].size() == 0);
                    BEAST_EXPECT(jp[jss::seq].asUInt() == 0);
                    BEAST_EXPECT(
                        jp[jss::pubkey_publisher] == strHex(publisherPublic));
                    BEAST_EXPECT(jp[jss::expiration] ==
                        to_string(TimeKeeper::time_point{}));
                }
            }
            {
                auto const jrr = env.rpc("validator_sites")[jss::result];
                if (BEAST_EXPECT(jrr[jss::validator_sites].size() == 1))
                {
                    auto js = jrr[jss::validator_sites][0u];
                    BEAST_EXPECT(js[jss::refresh_interval_min].asUInt() == 5);
                    BEAST_EXPECT(js[jss::uri] == siteURI);
                    BEAST_EXPECT(!js.isMember(jss::last_refresh_time));
                    BEAST_EXPECT(!js.isMember(jss::last_refresh_status));
                }
            }
        }
        //----------------------------------------------------------------------
        // Publisher list site available
        {
            NetClock::time_point const expiration{3600s};
            TrustedPublisherServer server(
                ep, publisherSigningKeys, manifest, 1, expiration, 1, keys);

            Env env{
                *this,
                envconfig([&](std::unique_ptr<Config> cfg) {
                    cfg->section(SECTION_VALIDATOR_LIST_SITES).append(siteURI);
                    cfg->section(SECTION_VALIDATOR_LIST_KEYS)
                        .append(strHex(publisherPublic));
                    return cfg;
                }),
            };

            env.app().validatorSites().start();
            env.app().validatorSites().join();
            env.app().validators().onConsensusStart(
                std::set<PublicKey>{keys.begin(), keys.end()});

            {
                auto const jrr = env.rpc("server_info")[jss::result];
                BEAST_EXPECT(jrr[jss::info][jss::validator_list_expires] ==
                    to_string(expiration));
            }
            {
                auto const jrr = env.rpc("server_state")[jss::result];
                BEAST_EXPECT(
                    jrr[jss::state][jss::validator_list_expires].asUInt() ==
                    expiration.time_since_epoch().count());
            }
            {
                auto const jrr = env.rpc("validator_lists")[jss::result];
                BEAST_EXPECT(jrr[jss::validation_quorum].asUInt() == 2);
                BEAST_EXPECT(
                    jrr[jss::validator_list_expires] == to_string(expiration));

                if (BEAST_EXPECT(jrr[jss::validator_keys].size() == 2))
                {
                    std::set<std::string> foundKeys;
                    for (auto const& jKeys : jrr[jss::validator_keys])
                    {
                        foundKeys.insert(
                            jKeys[jss::pubkey_validator].asString());
                    }
                    BEAST_EXPECT(foundKeys == expectedKeys);
                }

                if (BEAST_EXPECT(jrr[jss::publisher_lists].size() == 1))
                {
                    auto jp = jrr[jss::publisher_lists][0u];
                    BEAST_EXPECT(jp[jss::available] == true);
                    if (BEAST_EXPECT(jp[jss::list].size() == 2))
                    {
                        // check entries
                        std::set<std::string> foundKeys;
                        for (auto const& k : jp[jss::list])
                        {
                            foundKeys.insert(k.asString());
                        }
                        BEAST_EXPECT(foundKeys == expectedKeys);
                    }
                    BEAST_EXPECT(jp[jss::seq].asUInt() == 1);
                    BEAST_EXPECT(
                        jp[jss::pubkey_publisher] == strHex(publisherPublic));
                    BEAST_EXPECT(jp[jss::expiration] == to_string(expiration));
                }
            }
            {
                auto const jrr = env.rpc("validator_sites")[jss::result];
                if (BEAST_EXPECT(jrr[jss::validator_sites].size() == 1))
                {
                    auto js = jrr[jss::validator_sites][0u];
                    BEAST_EXPECT(js[jss::refresh_interval_min].asUInt() == 5);
                    BEAST_EXPECT(js[jss::uri] == siteURI);
                    BEAST_EXPECT(js[jss::last_refresh_status] == "accepted");
                    // The actual time of the udpate will vary run to run, so
                    // just verify the time is there
                    BEAST_EXPECT(js.isMember(jss::last_refresh_time));
                }
            }
        }
    }

    void
    run()
    {
        testPriviledges();
        testStaticUNL();
        testDynamicUNL();
    }
};

BEAST_DEFINE_TESTSUITE(ValidatorRPC, app, ripple);

}  // namespace test
}  // namespace ripple
