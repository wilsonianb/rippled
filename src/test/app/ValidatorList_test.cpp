//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright 2015 Ripple Labs Inc.

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

#include <beast/core/detail/base64.hpp>
#include <ripple/basics/Slice.h>
#include <ripple/basics/strHex.h>
#include <ripple/basics/TestSuite.h>
#include <ripple/app/misc/ValidatorList.h>
#include <ripple/protocol/digest.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/SecretKey.h>
#include <ripple/protocol/Sign.h>

namespace ripple {
namespace tests {

class ValidatorList_test : public beast::unit_test::suite
{
private:
    static
    PublicKey
    randomNode ()
    {
        return derivePublicKey (KeyType::secp256k1, randomSecretKey());
    }

    static
    PublicKey
    randomMasterKey ()
    {
        return derivePublicKey (KeyType::ed25519, randomSecretKey());
    }

    std::string
    makeManifestString (
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
        sign(st, HashPrefix::manifest, *publicKeyType(pk), sk,
            sfMasterSignature);

        Serializer s;
        st.add(s);

        return std::string(static_cast<char const*> (s.data()), s.size());
    }

    std::string
    makeList (
        std::vector <PublicKey> const& validators,
        std::size_t sequence)
    {
        std::string data =
            "{\"sequence\":" + std::to_string(sequence) + ",\"validators\":[";

        for (auto const& val : validators)
        {
            data += "{\"validation_public_key\":\"" +
                toBase58 (TokenType::TOKEN_NODE_PUBLIC, val) + "\"},";
        }
        data.pop_back();
        data += "]}";
        return beast::detail::base64_encode(data);
    }

    std::string
    signList (
        std::string const& blob,
        std::pair<PublicKey, SecretKey> const& keys)
    {
        auto const data = beast::detail::base64_decode (blob);
        return strHex(signDigest(
            keys.first, keys.second, sha512Half(makeSlice(data))));
    }

    void
    testConfigLoad ()
    {
        testcase ("Config Load");

        beast::Journal journal;
        PublicKey emptyLocalKey;
        std::vector<std::string> emptyCfgKeys;
        std::vector<std::string> emptyCfgPublishers;
        std::vector<std::string> emptyCfgManifest;

        auto const localSigningKeys = randomKeyPair(KeyType::secp256k1);
        auto const localSigningPublic = localSigningKeys.first;
        auto const localSigningSecret = localSigningKeys.second;
        auto const localMasterSecret = randomSecretKey();
        auto const localMasterPublic = derivePublicKey(
            KeyType::ed25519, localMasterSecret);

        std::vector<std::string> const cfgManifest ({
            beast::detail::base64_encode (makeManifestString (
                localMasterPublic, localMasterSecret,
                localSigningPublic, localSigningSecret, 1))});

        auto format = [](
            PublicKey const &publicKey,
            char const* comment = nullptr)
        {
            auto ret = toBase58 (TokenType::TOKEN_NODE_PUBLIC, publicKey);

            if (comment)
                ret += comment;

            return ret;
        };

        std::vector<PublicKey> configList;
        configList.reserve(8);

        while (configList.size () != 8)
            configList.push_back (randomNode());

        // Correct configuration
        std::vector<std::string> cfgKeys ({
            format (configList[0]),
            format (configList[1], " Comment"),
            format (configList[2], " Multi Word Comment"),
            format (configList[3], "    Leading Whitespace"),
            format (configList[4], " Trailing Whitespace    "),
            format (configList[5], "    Leading & Trailing Whitespace    "),
            format (configList[6], "    Leading, Trailing & Internal    Whitespace    "),
            format (configList[7], "    ")
        });

        {
            ManifestCache manifests;
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, journal);

            // Correct (empty) configuration
            BEAST_EXPECT(trustedKeys->load (
                emptyLocalKey, emptyCfgKeys,
                emptyCfgPublishers, emptyCfgManifest));

            // load local validator key with or without manifest
            BEAST_EXPECT(trustedKeys->load (
                localSigningPublic, emptyCfgKeys,
                emptyCfgPublishers, emptyCfgManifest));
            BEAST_EXPECT(trustedKeys->listed (localSigningPublic));

            BEAST_EXPECT(trustedKeys->load (
                localSigningPublic, emptyCfgKeys,
                emptyCfgPublishers, cfgManifest));
            BEAST_EXPECT(trustedKeys->listed (localMasterPublic));
            BEAST_EXPECT(trustedKeys->listed (localSigningPublic));

            // load should reject invalid config manifests
            auto const signingKeys = randomKeyPair(KeyType::secp256k1);
            std::vector<std::string> const badManifest ({
                beast::detail::base64_encode (makeManifestString (
                    localMasterPublic, localMasterSecret,
                    signingKeys.first, signingKeys.second, 2))});

            BEAST_EXPECT(! trustedKeys->load (
                localSigningPublic, emptyCfgKeys,
                emptyCfgPublishers, badManifest));

            std::vector<std::string> const revokedManifest ({
                beast::detail::base64_encode (makeManifestString (
                    localMasterPublic, localMasterSecret,
                    localSigningPublic, localSigningSecret,
                    std::numeric_limits<std::uint32_t>::max ()))});

            BEAST_EXPECT(! trustedKeys->load (
                localSigningPublic, emptyCfgKeys,
                emptyCfgPublishers, revokedManifest));
        }
        {
            // load should add validator keys from config
            ManifestCache manifests;
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, journal);

            BEAST_EXPECT(trustedKeys->load (
                emptyLocalKey, cfgKeys,
                emptyCfgPublishers, emptyCfgManifest));

            for (auto const& n : configList)
                BEAST_EXPECT(trustedKeys->listed (n));

            // load should accept Ed25519 master public keys
            auto const masterNode1 = randomMasterKey ();
            auto const masterNode2 = randomMasterKey ();

            std::vector<std::string> cfgMasterKeys({
                format (masterNode1),
                format (masterNode2, " Comment")
            });
            BEAST_EXPECT(trustedKeys->load (
                emptyLocalKey, cfgMasterKeys,
                emptyCfgPublishers, emptyCfgManifest));
            BEAST_EXPECT(trustedKeys->listed (masterNode1));
            BEAST_EXPECT(trustedKeys->listed (masterNode2));

            // load should reject invalid config keys
            std::vector<std::string> badKeys({"NotAPublicKey"});
            BEAST_EXPECT(!trustedKeys->load (
                emptyLocalKey, badKeys,
                emptyCfgPublishers, emptyCfgManifest));

            badKeys[0] = format (randomNode(), "!");
            BEAST_EXPECT(!trustedKeys->load (
                emptyLocalKey, badKeys,
                emptyCfgPublishers, emptyCfgManifest));

            badKeys[0] = format (randomNode(), "!  Comment");
            BEAST_EXPECT(!trustedKeys->load (
                emptyLocalKey, badKeys,
                emptyCfgPublishers, emptyCfgManifest));

            // load terminates when encountering an invalid entry
            auto const goodKey = randomNode();
            badKeys.push_back (format (goodKey));
            BEAST_EXPECT(!trustedKeys->load (
                emptyLocalKey, badKeys,
                emptyCfgPublishers, emptyCfgManifest));
            BEAST_EXPECT(!trustedKeys->listed (goodKey));
        }
        {
            // local validator key on config list
            ManifestCache manifests;
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, journal);

            auto const localSigningPublic = parseBase58<PublicKey> (
                TokenType::TOKEN_NODE_PUBLIC, cfgKeys.front());

            BEAST_EXPECT(trustedKeys->load (
                *localSigningPublic, cfgKeys,
                emptyCfgPublishers, emptyCfgManifest));

            BEAST_EXPECT(trustedKeys->listed (*localSigningPublic));
            for (auto const& n : configList)
                BEAST_EXPECT(trustedKeys->listed (n));
        }
        {
            // local validator key not on config list
            ManifestCache manifests;
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, journal);

            auto const localSigningPublic = randomNode();
            BEAST_EXPECT(trustedKeys->load (
                localSigningPublic, cfgKeys,
                emptyCfgPublishers, emptyCfgManifest));

            BEAST_EXPECT(trustedKeys->listed (localSigningPublic));
            for (auto const& n : configList)
                BEAST_EXPECT(trustedKeys->listed (n));
        }
        {
            // local validator key (with manifest) not on config list
            ManifestCache manifests;
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, journal);

            BEAST_EXPECT(trustedKeys->load (
                localSigningPublic, cfgKeys,
                emptyCfgPublishers, cfgManifest));

            BEAST_EXPECT(trustedKeys->listed (localSigningPublic));
            BEAST_EXPECT(trustedKeys->listed (localMasterPublic));
            for (auto const& n : configList)
                BEAST_EXPECT(trustedKeys->listed (n));
        }
        {
            ManifestCache manifests;
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, journal);

            // load should reject invalid validator list signing keys
            std::vector<std::string> badPublishers(
                {"NotASigningKey"});
            BEAST_EXPECT(!trustedKeys->load (
                emptyLocalKey, emptyCfgKeys,
                badPublishers, emptyCfgManifest));

            // load should reject validator list signing keys with invalid encoding
            std::vector<PublicKey> keys ({
                randomMasterKey(), randomMasterKey(), randomMasterKey()});
            badPublishers.clear();
            for (auto const& key : keys)
                badPublishers.push_back (
                    toBase58 (TokenType::TOKEN_NODE_PUBLIC, key));

            BEAST_EXPECT(! trustedKeys->load (
                emptyLocalKey, emptyCfgKeys,
                badPublishers, emptyCfgManifest));
            for (auto const& key : keys)
                BEAST_EXPECT(!trustedKeys->trustedPublisher (key));

            // load should accept valid validator list publisher keys
            std::vector<std::string> cfgPublishers;
            for (auto const& key : keys)
                cfgPublishers.push_back (
                    toBase58 (TokenType::TOKEN_ACCOUNT_PUBLIC, key));

            BEAST_EXPECT(trustedKeys->load (
                emptyLocalKey, emptyCfgKeys,
                cfgPublishers, emptyCfgManifest));
            for (auto const& key : keys)
                BEAST_EXPECT(trustedKeys->trustedPublisher (key));
        }
    }

    void
    testApplyList ()
    {
        testcase ("Apply list");

        beast::Journal journal;
        ManifestCache manifests;
        auto trustedKeys = std::make_unique<ValidatorList> (
            manifests, journal);

        auto const masterSecret1 = randomSecretKey();
        auto const masterPublic1 =
            derivePublicKey(KeyType::ed25519, masterSecret1);
        std::vector<std::string> cfgKeys1({
            toBase58(TokenType::TOKEN_ACCOUNT_PUBLIC, masterPublic1)});
        PublicKey emptyLocalKey;
        std::vector<std::string> emptyCfgKeys;
        std::vector<std::string> emptyCfgManifest;

        BEAST_EXPECT(trustedKeys->load (
            emptyLocalKey, emptyCfgKeys,
            cfgKeys1, emptyCfgManifest));

        auto const signingKeys1 = randomKeyPair(KeyType::secp256k1);

        auto manifest1 = Manifest::make_Manifest (makeManifestString (
            masterPublic1, masterSecret1,
            signingKeys1.first, signingKeys1.second, 1));
        manifests.applyManifest (std::move (*manifest1), *trustedKeys);

        auto constexpr listSize = 20;
        std::vector<PublicKey> list1;
        list1.reserve (listSize);
        while (list1.size () < listSize)
            list1.push_back (randomNode());

        std::vector<PublicKey> list2;
        list2.reserve (listSize);
        while (list2.size () < listSize)
            list2.push_back (randomNode());

        // apply single list
        auto const version = 1;
        auto const sequence = 1;
        auto const blob1 = makeList (list1, sequence);
        auto const sig1 = signList (blob1, signingKeys1);

        BEAST_EXPECT(ListDisposition::accepted == trustedKeys->applyList (
            masterPublic1, blob1, sig1, version));

        for (auto const& val : list1)
            BEAST_EXPECT(trustedKeys->listed (val));

        // do not use list from untrusted publisher
        BEAST_EXPECT(ListDisposition::untrusted == trustedKeys->applyList (
            randomMasterKey(), blob1, sig1, version));

        // do not use list with unhandled version
        auto const badVersion = 666;
        BEAST_EXPECT(ListDisposition::unsupported_version ==
            trustedKeys->applyList (
                masterPublic1, blob1, sig1, badVersion));

        // apply list with highest sequence number
        auto const sequence2 = 2;
        auto const blob2 = makeList (list2, sequence2);
        auto const sig2 = signList (blob2, signingKeys1);

        BEAST_EXPECT(ListDisposition::accepted ==
            trustedKeys->applyList (
                masterPublic1, blob2, sig2, version));

        for (auto const& val : list1)
            BEAST_EXPECT(! trustedKeys->listed (val));

        for (auto const& val : list2)
            BEAST_EXPECT(trustedKeys->listed (val));

        // do not re-apply lists with past or current sequence numbers
        BEAST_EXPECT(ListDisposition::stale ==
            trustedKeys->applyList (
                masterPublic1, blob1, sig1, version));

        BEAST_EXPECT(ListDisposition::stale ==
            trustedKeys->applyList (
                masterPublic1, blob2, sig2, version));

        // apply list with new publisher key updated by manifest
        auto const signingKeys2 = randomKeyPair(KeyType::secp256k1);
        auto manifest2 = Manifest::make_Manifest(makeManifestString (
            masterPublic1, masterSecret1,
            signingKeys2.first, signingKeys2.second, 2));
        manifests.applyManifest (std::move (*manifest2), *trustedKeys);

        auto const sequence3 = 3;
        auto const blob3 = makeList (list1, sequence3);
        auto const sig3 = signList (blob3, signingKeys2);

        BEAST_EXPECT(ListDisposition::accepted ==
            trustedKeys->applyList (
                masterPublic1, blob3, sig3, version));

        BEAST_EXPECT(ListDisposition::invalid ==
            trustedKeys->applyList (
                masterPublic1, blob2, sig2, version));

        // applied list is removed due to revoked publisher key
        auto const signingKeysMax = randomKeyPair(KeyType::secp256k1);
        auto maxManifest = Manifest::make_Manifest(makeManifestString (
                masterPublic1, masterSecret1,
                signingKeysMax.first, signingKeysMax.second,
                std::numeric_limits<std::uint32_t>::max ()));
        manifests.applyManifest (std::move (*maxManifest), *trustedKeys);

        for (auto const& val : list1)
            BEAST_EXPECT(! trustedKeys->listed (val));

        // do not apply list with revoked publisher key
        auto const sequence4 = 4;
        auto const blob4 = makeList (list2, sequence4);
        auto const sig4 = signList (blob4, signingKeysMax);

        BEAST_EXPECT(ListDisposition::untrusted ==
            trustedKeys->applyList (
                masterPublic1, blob2, sig2, version));
    }

    void
    testUpdate ()
    {
        testcase ("Update");

        PublicKey emptyLocalKey;
        ManifestCache manifests;
        auto trustedKeys = std::make_unique <ValidatorList> (
            manifests, beast::Journal ());

        std::vector<std::string> cfgPublishers;
        std::vector<std::string> emptyCfgManifest;
        hash_set<PublicKey> activeValidators;

        {
            std::vector<std::string> cfgKeys;
            cfgKeys.reserve(20);

            while (cfgKeys.size () != 20)
            {
                auto const valKey = randomNode();
                cfgKeys.push_back (toBase58(
                    TokenType::TOKEN_NODE_PUBLIC, valKey));
                if (cfgKeys.size () <= 15)
                    activeValidators.emplace (valKey);
            }

            BEAST_EXPECT(trustedKeys->load (
                emptyLocalKey, cfgKeys,
                cfgPublishers, emptyCfgManifest));

            // onConsensusStart should make all available configured
            // validators trusted
            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->quorum () == 12);
            auto i = 0;
            for (auto const& val : cfgKeys)
            {
                if (auto const valKey = parseBase58<PublicKey>(
                    TokenType::TOKEN_NODE_PUBLIC, val))
                {
                    BEAST_EXPECT(trustedKeys->listed (*valKey));
                    if (i++ < activeValidators.size ())
                        BEAST_EXPECT(trustedKeys->trusted (*valKey));
                    else
                        BEAST_EXPECT(!trustedKeys->trusted (*valKey));
                }
                else
                    fail ();
            }
        }
        {
            // update with manifests
            auto const masterPrivate  = randomSecretKey();
            auto const masterPublic =
                derivePublicKey(KeyType::ed25519, masterPrivate);

            std::vector<std::string> cfgKeys ({
                toBase58 (TokenType::TOKEN_NODE_PUBLIC, masterPublic)});

            BEAST_EXPECT(trustedKeys->load (
                emptyLocalKey, cfgKeys,
                cfgPublishers, emptyCfgManifest));

            auto const signingKeys1 = randomKeyPair(KeyType::secp256k1);
            auto const signingPublic1 = signingKeys1.first;
            activeValidators.emplace (masterPublic);

            // Should not trust ephemeral signing key if there is no manifest
            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->listed (masterPublic));
            BEAST_EXPECT(trustedKeys->trusted (masterPublic));
            BEAST_EXPECT(!trustedKeys->listed (signingPublic1));
            BEAST_EXPECT(!trustedKeys->trusted (signingPublic1));

            // Should trust the ephemeral signing key from the applied manifest
            auto m1 = Manifest::make_Manifest (makeManifestString (
                masterPublic, masterPrivate,
                signingPublic1, signingKeys1.second, 1));

            BEAST_EXPECT(
                manifests.applyManifest(std::move (*m1), *trustedKeys) ==
                    ManifestDisposition::accepted);
            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->quorum () == 13);
            BEAST_EXPECT(trustedKeys->listed (masterPublic));
            BEAST_EXPECT(trustedKeys->trusted (masterPublic));
            BEAST_EXPECT(trustedKeys->listed (signingPublic1));
            BEAST_EXPECT(trustedKeys->trusted (signingPublic1));

            // Should only trust the ephemeral signing key
            // from the newest applied manifest
            auto const signingKeys2 = randomKeyPair(KeyType::secp256k1);
            auto const signingPublic2 = signingKeys2.first;
            auto m2 = Manifest::make_Manifest (makeManifestString (
                masterPublic, masterPrivate,
                signingPublic2, signingKeys2.second, 2));

            BEAST_EXPECT(
                manifests.applyManifest(std::move (*m2), *trustedKeys) ==
                    ManifestDisposition::accepted);
            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->quorum () == 13);
            BEAST_EXPECT(trustedKeys->listed (masterPublic));
            BEAST_EXPECT(trustedKeys->trusted (masterPublic));
            BEAST_EXPECT(trustedKeys->listed (signingPublic2));
            BEAST_EXPECT(trustedKeys->trusted (signingPublic2));
            BEAST_EXPECT(!trustedKeys->listed (signingPublic1));
            BEAST_EXPECT(!trustedKeys->trusted (signingPublic1));

            // Should not trust keys from revoked master public key
            auto const signingKeysMax = randomKeyPair(KeyType::secp256k1);
            auto const signingPublicMax = signingKeysMax.first;
            activeValidators.emplace (signingPublicMax);
            auto mMax = Manifest::make_Manifest (makeManifestString (
                masterPublic, masterPrivate,
                signingPublicMax, signingKeysMax.second,
                std::numeric_limits<std::uint32_t>::max ()));

            BEAST_EXPECT(mMax->revoked ());
            BEAST_EXPECT(
                manifests.applyManifest(std::move (*mMax), *trustedKeys) ==
                    ManifestDisposition::accepted);
            BEAST_EXPECT(manifests.getSigningKey (masterPublic) == masterPublic);
            BEAST_EXPECT(manifests.revoked (masterPublic));
            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->quorum () == 12);
            BEAST_EXPECT(trustedKeys->listed (masterPublic));
            BEAST_EXPECT(!trustedKeys->trusted (masterPublic));
            BEAST_EXPECT(!trustedKeys->listed (signingPublicMax));
            BEAST_EXPECT(!trustedKeys->trusted (signingPublicMax));
            BEAST_EXPECT(!trustedKeys->listed (signingPublic2));
            BEAST_EXPECT(!trustedKeys->trusted (signingPublic2));
            BEAST_EXPECT(!trustedKeys->listed (signingPublic1));
            BEAST_EXPECT(!trustedKeys->trusted (signingPublic1));
        }
        {
            // Should use custom minimum quorum
            auto const minQuorum = 0;
            ManifestCache manifests;
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, beast::Journal (), minQuorum);

            auto const node = randomNode ();
            std::vector<std::string> cfgKeys ({
                toBase58 (TokenType::TOKEN_NODE_PUBLIC, node)});
            hash_set<PublicKey> activeValidators;

            BEAST_EXPECT(trustedKeys->load (
                emptyLocalKey, cfgKeys,
                cfgPublishers, emptyCfgManifest));

            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->quorum () == minQuorum);

            activeValidators.emplace (node);
            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->quorum () == 1);
        }
        {
            // Increase quorum when running as an unlisted validator
            auto trustedKeys = std::make_unique <ValidatorList> (
                manifests, beast::Journal ());

            std::vector<PublicKey> keys ({ randomNode (), randomNode () });
            hash_set<PublicKey> activeValidators ({ keys[0], keys[1] });
            std::vector<std::string> cfgKeys ({
                toBase58 (TokenType::TOKEN_NODE_PUBLIC, keys[0]),
                toBase58 (TokenType::TOKEN_NODE_PUBLIC, keys[1])});

            auto const localKey = randomNode ();
            BEAST_EXPECT(trustedKeys->load (
                localKey, cfgKeys,
                cfgPublishers, emptyCfgManifest));

            trustedKeys->onConsensusStart (activeValidators);
            BEAST_EXPECT(trustedKeys->quorum () == 3);

            // local validator key is always trusted
            BEAST_EXPECT(trustedKeys->trusted (localKey));
        }
    }

public:
    void
    run() override
    {
        testConfigLoad ();
        testApplyList ();
        testUpdate ();
    }
};

BEAST_DEFINE_TESTSUITE(ValidatorList, app, ripple);

} // tests
} // ripple
