//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2015 Ripple Labs Inc.

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

#include <ripple/app/misc/ValidatorList.h>
#include <ripple/basics/Slice.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/beast/rfc2616.h>
#include <ripple/json/json_reader.h>
#include <beast/core/detail/base64.hpp>
#include <boost/regex.hpp>

namespace ripple {

ValidatorList::ValidatorList (
    ManifestCache& manifests,
    beast::Journal j,
    boost::optional<std::size_t> minimumQuorum)
    : manifests_ (manifests)
    , j_ (j)
    , quorum_ (0)
    , minimumQuorum_ (minimumQuorum)
{
}

ValidatorList::~ValidatorList()
{
}

bool
ValidatorList::load (
    PublicKey const& localSigningKey,
    std::vector<std::string> const& configKeys,
    std::vector<std::string> const& publisherKeys,
    std::vector<std::string> const& configManifest)
{
    static boost::regex const re (
        "[[:space:]]*"            // skip leading whitespace
        "([[:alnum:]]+)"          // node identity
        "(?:"                     // begin optional comment block
        "[[:space:]]+"            // (skip all leading whitespace)
        "(?:"                     // begin optional comment
        "(.*[^[:space:]]+)"       // the comment
        "[[:space:]]*"            // (skip all trailing whitespace)
        ")?"                      // end optional comment
        ")?"                      // end optional comment block
    );

    boost::unique_lock<boost::shared_mutex> read_lock{mutex_};

    JLOG (j_.debug()) <<
        "Loading configured trusted validator list publisher keys";

    std::size_t count = 0;
    for (auto key : publisherKeys)
    {
        JLOG (j_.trace()) <<
            "Processing '" << key << "'";

        auto const id = parseBase58<PublicKey>(
            TokenType::TOKEN_ACCOUNT_PUBLIC, key);

        if (!id)
        {
            JLOG (j_.error()) <<
                "Invalid validator list signing key: " << key;
            return false;
        }

        if (publisherLists_.count(*id))
        {
            JLOG (j_.warn()) <<
                "Duplicate validator list signing key: " << key;
            continue;
        }
        publisherLists_[*id];
        ++count;
    }

    JLOG (j_.debug()) <<
        "Loaded " << count << " keys";

    localPubKey_ = localSigningKey;
    boost::optional<Manifest> mo;
    if (! configManifest.empty())
    {
        std::string s;
        s.reserve (Manifest::textLength);
        for (auto const& line : configManifest)
            s += beast::rfc2616::trim(line);

        mo = Manifest::make_Manifest (beast::detail::base64_decode(s));
        if (mo)
        {
            if (mo->signingKey != localPubKey_)
            {
                JLOG (j_.error()) <<
                    "Configured manifest's signing public key does not " <<
                    "match configured validation seed";
                return false;
            }

            if (mo->revoked())
            {
                JLOG (j_.error()) <<
                    "Configured manifest revokes validation signing public key";
                return false;
            }

            localPubKey_ = mo->masterKey;
        }
        else
        {
            JLOG (j_.error()) << "Malformed manifest in config";
            return false;
        }
    }
    else
    {
        JLOG (j_.debug()) << "No validation manifest in config";
    }

    // Treat local validator key as though it was listed in the config
    if (localPubKey_.size())
        keyListings_.insert ({ localPubKey_, 1 });

    read_lock.unlock();
    if (mo &&
        manifests_.applyManifest (std::move(*mo), *this) !=
            ManifestDisposition::accepted)
    {
        JLOG (j_.error()) << "Validation manifest in config was rejected";
        return false;
    }

    JLOG (j_.debug()) <<
        "Loading configured validator keys";

    read_lock.lock();

    count = 0;
    PublicKey local;
    for (auto const& n : configKeys)
    {
        JLOG (j_.trace()) <<
            "Processing '" << n << "'";

        boost::smatch match;

        if (!boost::regex_match (n, match, re))
        {
            JLOG (j_.error()) <<
                "Malformed entry: '" << n << "'";
            return false;
        }

        auto const id = parseBase58<PublicKey>(
            TokenType::TOKEN_NODE_PUBLIC, match[1]);

        if (!id)
        {
            JLOG (j_.error()) << "Invalid node identity: " << match[1];
            return false;
        }

        // Skip local key which was already added
        if (*id == localPubKey_ || *id == localSigningKey)
            continue;

        auto ret = keyListings_.insert ({*id, 1});
        if (! ret.second)
        {
            JLOG (j_.warn()) << "Duplicate node identity: " << match[1];
            continue;
        }
        publisherLists_[local].list.emplace_back (std::move(*id));
        ++count;
    }

    JLOG (j_.debug()) <<
        "Loaded " << count << " entries";

    return true;
}


ListDisposition
ValidatorList::applyList (
    PublicKey const& pubKey,
    std::string const& blob,
    std::string const& signature,
    std::uint32_t version)
{
    if (version != 1)
        return ListDisposition::unsupported_version;

    Json::Value list;
    auto const result = verify (list, pubKey, blob, signature);
    if (result != ListDisposition::accepted)
        return result;

    boost::unique_lock<boost::shared_mutex> read_lock{mutex_};

    // Update publisher's list
    Json::Value const& newList = list["validators"];
    publisherLists_[pubKey].sequence = list["sequence"].asUInt ();
    std::vector<PublicKey>& publisherList = publisherLists_[pubKey].list;

    std::vector<PublicKey> oldList = publisherList;
    publisherList.clear ();
    publisherList.reserve (newList.size ());
    for (auto const& val : newList)
    {
        if (val.isObject () &&
            val.isMember ("validation_public_key") &&
            val["validation_public_key"].isString ())
        {
            auto const id = parseBase58<PublicKey>(
                TokenType::TOKEN_NODE_PUBLIC,
                val["validation_public_key"].asString ());

            if (! id)
                JLOG (j_.error()) <<
                    "Invalid node identity: " <<
                    val["validation_public_key"].asString ();
            else
                publisherList.push_back (*id);
        }
    }

    // Update keyListings_ for added and removed keys
    std::sort (
        publisherList.begin (),
        publisherList.end ());

    auto iNew = publisherList.begin ();
    auto iOld = oldList.begin ();
    while (iNew != publisherList.end () ||
        iOld != oldList.end ())
    {
        if (iOld == oldList.end () ||
            (iNew != publisherList.end () &&
            *iNew < *iOld))
        {
            // Increment list count for added keys
            ++keyListings_[*iNew];
            ++iNew;
        }
        else if (iNew == publisherList.end () ||
            (iOld != oldList.end () && *iOld < *iNew))
        {
            // Decrement list count for removed keys
            if (keyListings_[*iOld] == 1)
                keyListings_.erase (*iOld);
            else
                --keyListings_[*iOld];
            ++iOld;
        }
        else
        {
            ++iNew;
            ++iOld;
        }
    }

    if (publisherList.empty())
    {
        JLOG (j_.warn()) <<
            "No validator keys included in valid list";
    }

    read_lock.unlock();

    return ListDisposition::accepted;
}

ListDisposition
ValidatorList::verify (
    Json::Value& list,
    PublicKey const& pubKey,
    std::string const& blob,
    std::string const& signature)
{
    boost::shared_lock<boost::shared_mutex> read_lock{mutex_};

    auto iter = publisherLists_.find (pubKey);
    if (iter == publisherLists_.end ())
        return ListDisposition::untrusted;

    auto const sig = strUnHex(signature);
    auto const data = beast::detail::base64_decode (blob);
    if (! sig.second ||
        ! ripple::verify (
            manifests_.getSigningKey (pubKey),
            makeSlice(data),
            makeSlice(sig.first)))
        return ListDisposition::invalid;

    Json::Reader r;
    if (! r.parse (data, list))
        return ListDisposition::invalid;

    if (list.isMember("sequence") && list["sequence"].isInt() &&
        list.isMember("validators") && list["validators"].isArray())
    {
        auto const sequence = list["sequence"].asUInt ();
        if (sequence <= iter->second.sequence)
            return ListDisposition::stale;
    }
    else
    {
        return ListDisposition::invalid;
    }

    return ListDisposition::accepted;
}

bool
ValidatorList::listed (
    PublicKey const& identity) const
{
    boost::shared_lock<boost::shared_mutex> read_lock{mutex_};

    auto const pubKey = manifests_.getMasterKey (identity);
    return keyListings_.find (pubKey) != keyListings_.end ();
}

bool
ValidatorList::trusted (PublicKey const& identity) const
{
    boost::shared_lock<boost::shared_mutex> read_lock{mutex_};

    auto const pubKey = manifests_.getMasterKey (identity);
    return trustedKeys_.find (pubKey) != trustedKeys_.end();
}

boost::optional<PublicKey>
ValidatorList::getListedKey (
    PublicKey const& identity) const
{
    boost::shared_lock<boost::shared_mutex> read_lock{mutex_};

    auto const pubKey = manifests_.getMasterKey (identity);
    if (keyListings_.find (pubKey) != keyListings_.end ())
        return pubKey;
    return boost::none;
}

boost::optional<PublicKey>
ValidatorList::getTrustedKey (PublicKey const& identity) const
{
    boost::shared_lock<boost::shared_mutex> read_lock{mutex_};

    auto const pubKey = manifests_.getMasterKey (identity);
    if (trustedKeys_.find (pubKey) != trustedKeys_.end())
        return pubKey;
    return boost::none;
}

bool
ValidatorList::trustedPublisher (PublicKey const& identity) const
{
    boost::shared_lock<boost::shared_mutex> read_lock{mutex_};
    return identity.size() && publisherLists_.count (identity);
}

bool
ValidatorList::removePublisher (PublicKey const& publisherKey)
{
    boost::unique_lock<boost::shared_mutex> read_lock{mutex_};

    auto const iList = publisherLists_.find (publisherKey);
    if (iList == publisherLists_.end ())
        return false;

    JLOG (j_.debug()) <<
        "Removing validator list for revoked publisher " <<
        toBase58(TokenType::TOKEN_NODE_PUBLIC, publisherKey);

    for (auto const& val : iList->second.list)
    {
        auto const& iVal = keyListings_.find (val);
        if (iVal == keyListings_.end())
            continue;

        if (iVal->second <= 1)
            keyListings_.erase (iVal);
        else
            --iVal->second;
    }

    publisherLists_.erase (iList);
    return true;
}

void
ValidatorList::for_each_listed (
    std::function<void(PublicKey const&, bool)> func) const
{
    boost::shared_lock<boost::shared_mutex> read_lock{mutex_};

    for (auto const& v : keyListings_)
        func (v.first, trusted(v.first));
}

} // ripple
