//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012, 2013 Ripple Labs Inc.

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
#include <ripple/app/misc/Validations.h>
#include <ripple/core/DatabaseCon.h>
#include <ripple/app/ledger/LedgerMaster.h>
#include <ripple/consensus/LedgerTiming.h>
#include <ripple/app/main/Application.h>
#include <ripple/app/misc/NetworkOPs.h>
#include <ripple/app/misc/ValidatorList.h>
#include <ripple/basics/Log.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/basics/chrono.h>
#include <ripple/beast/container/aged_unordered_map.h>
#include <ripple/core/JobQueue.h>
#include <ripple/core/TimeKeeper.h>
#include <memory>
#include <mutex>
#include <thread>

namespace ripple {

class ValidationsImp : public Validations
{
private:
    using LockType = std::mutex;
    using ScopedLockType = std::lock_guard <LockType>;
    using ScopedUnlockType = GenericScopedUnlock <LockType>;

    Application& app_;
    std::mutex mutable mLock;

    static constexpr std::chrono::seconds expireAge = std::chrono::seconds{600};
    beast::aged_unordered_map<uint256, ValidationSet, Stopwatch::clock_type,
        beast::uhash<>> mValidations;
    ValidationSet mCurrentValidations;
    std::vector<STValidation::pointer> mStaleValidations;

    bool mWriting;
    beast::Journal j_;

private:
    ValidationSet * findCreateSet (uint256 const& ledgerHash)
    {
        return &mValidations[ledgerHash];
    }

    ValidationSet * findSet (uint256 const& ledgerHash)
    {
        auto it = mValidations.find(ledgerHash);
        if(it != mValidations.end())
            return &it->second;
        return nullptr;
    }


    //! Helper to iterate current validations, potentially clearing out stale ones
    template <class F>
    void forEachCurrent(bool checkStale, F && f)
    {
        auto it = mCurrentValidations.begin ();

        while (it != mCurrentValidations.end ())
        {
            if (checkStale && ! current (it->second))
            {
                // contains a stale record
                mStaleValidations.push_back (it->second);
                it = mCurrentValidations.erase (it);
                condWrite ();
            }
            else
            {
                // contains a live record
                f(it->first, it->second);
                ++it;
            }
        }
    }

public:
    explicit
    ValidationsImp (Application& app)
        : app_ (app)
        , mValidations (stopwatch())
        , mWriting (false)
        , j_ (app.journal ("Validations"))
    {
        mStaleValidations.reserve (512);
    }

private:
    bool addValidation (STValidation::ref val, std::string const& source) override
    {
        auto signer = val->getSignerPublic ();
        auto hash = val->getLedgerHash ();
        bool isCurrent = current (val);

        auto pubKey = app_.validators ().getTrustedKey (signer);

        if (!val->isTrusted() && pubKey)
            val->setTrusted();

        if (!val->isTrusted ())
        {
            JLOG (j_.trace()) <<
                "Node " << toBase58 (TokenType::TOKEN_NODE_PUBLIC, signer) <<
                " not in UNL st=" << val->getSignTime().time_since_epoch().count() <<
                ", hash=" << hash <<
                ", shash=" << val->getSigningHash () <<
                " src=" << source;
        }

        if (! pubKey)
            pubKey = app_.validators ().getListedKey (signer);

        if (isCurrent &&
            (val->isTrusted () || pubKey))
        {
            ScopedLockType sl (mLock);

            if (!findCreateSet (hash)->emplace(*pubKey, val).second)
                return false;

            auto res = mCurrentValidations.emplace(*pubKey,val);

            // previous validation existed
            if (!res.second)
            {
                auto it = res.first;
                auto const oldSeq = (*it->second)[~sfLedgerSequence];
                auto const newSeq = (*val)[~sfLedgerSequence];

                if (oldSeq && newSeq && *oldSeq == *newSeq)
                {
                    JLOG (j_.warn()) <<
                        "Trusted node " <<
                        toBase58 (TokenType::TOKEN_NODE_PUBLIC, *pubKey) <<
                        " published multiple validations for ledger " <<
                        *oldSeq;

                    // Remove current validation for the revoked signing key
                    if (signer != it->second->getSignerPublic())
                    {
                        auto set = findSet (it->second->getLedgerHash ());
                        if (set)
                            set->erase (*pubKey);
                    }
                }

                if (val->getSignTime () > it->second->getSignTime () ||
                    signer != it->second->getSignerPublic())
                {
                    // This is either a newer validation or a new signing key
                    val->setPreviousHash (it->second->getLedgerHash ());
                    mStaleValidations.push_back (it->second);
                    it->second = val;
                    condWrite ();
                }
                else
                {
                    // We already have a newer validation from this source
                    isCurrent = false;
                }
            }
        }

        JLOG (j_.debug()) <<
            "Val for " << hash <<
            " from " << toBase58 (TokenType::TOKEN_NODE_PUBLIC, signer) <<
            " added " << (val->isTrusted () ? "trusted/" : "UNtrusted/") <<
            (isCurrent ? "current" : "stale");

        if (val->isTrusted () && isCurrent)
        {
            app_.getLedgerMaster ().checkAccept (hash, val->getFieldU32 (sfLedgerSequence));
            return true;
        }

        // FIXME: This never forwards untrusted validations
        return false;
    }

    bool current (STValidation::ref val) override
    {
        // Because this can be called on untrusted, possibly
        // malicious validations, we do our math in a way
        // that avoids any chance of overflowing or underflowing
        // the signing time.

        auto const now = app_.timeKeeper().closeTime();
        auto const signTime = val->getSignTime();

        return
            (signTime > (now - VALIDATION_VALID_EARLY)) &&
            (signTime < (now + VALIDATION_VALID_WALL)) &&
            ((val->getSeenTime() == NetClock::time_point{}) ||
                (val->getSeenTime() < (now + VALIDATION_VALID_LOCAL)));
    }


    ValidationSet getValidations (uint256 const& ledger) override
    {
        {
            ScopedLockType sl (mLock);
            auto set = findSet (ledger);

            if (set)
                return *set;
        }
        return ValidationSet ();
    }

    std::vector<NetClock::time_point>
    getValidationTimes (uint256 const& hash) override
    {
        std::vector <NetClock::time_point> times;
        ScopedLockType sl (mLock);
        if (auto j = findSet (hash))
            for (auto& it : *j)
                if (it.second->isTrusted())
                    times.push_back (it.second->getSignTime());
        return times;
    }

    std::size_t
    getTrustedValidationCount (uint256 const& ledger) override
    {
        std::size_t trusted = 0;
        ScopedLockType sl (mLock);
        auto set = findSet (ledger);

        if (set)
        {
            for (auto& it: *set)
            {
                if (it.second->isTrusted ())
                    ++trusted;
            }
        }

        return trusted;
    }

    std::vector <std::uint64_t>
    fees (uint256 const& ledger, std::uint64_t base) override
    {
        std::vector <std::uint64_t> result;
        std::lock_guard <std::mutex> lock (mLock);
        auto const set = findSet (ledger);
        if (set)
        {
            for (auto const& v : *set)
            {
                if (v.second->isTrusted())
                {
                    if (v.second->isFieldPresent(sfLoadFee))
                        result.push_back(v.second->getFieldU32(sfLoadFee));
                    else
                        result.push_back(base);
                }
            }
        }

        return result;
    }

    int getNodesAfter (uint256 const& ledger) override
    {
        // Number of trusted nodes that have moved past this ledger
        int count = 0;
        ScopedLockType sl (mLock);
        forEachCurrent(false /*no stale check*/, [&](auto const &, auto const & v)
        {
            if(v->isTrusted() && v->isPreviousHash (ledger))
                count++;
        });

        return count;
    }

    int getLoadRatio (bool overLoaded) override
    {
        // how many trusted nodes are able to keep up, higher is better
        int goodNodes = overLoaded ? 1 : 0;
        int badNodes = overLoaded ? 0 : 1;
        ScopedLockType sl (mLock);
        forEachCurrent(false /* no stale check*/, [&](auto const &, auto const & v)
        {
                 if (v->isTrusted ())
                {
                    if (v->isFull ())
                        ++goodNodes;
                    else
                        ++badNodes;
                }
        });
        return (goodNodes * 100) / (goodNodes + badNodes);
    }

    std::list<STValidation::pointer> getCurrentTrustedValidations () override
    {
        std::list<STValidation::pointer> ret;

        ScopedLockType sl (mLock);

        forEachCurrent(true /* stale check*/, [&](auto const &, auto const & v)
        {
            if(v->isTrusted())
                ret.push_back(v);
        });
        return ret;
    }

    hash_set<PublicKey> getCurrentPublicKeys () override
    {
        hash_set<PublicKey> ret;

        ScopedLockType sl (mLock);
        forEachCurrent(true /* stale check*/, [&](auto const & k, auto const &)
        {
            ret.insert(k);
        });

        return ret;
    }

    LedgerToValidationCounter
    getCurrentValidations(
        uint256 currentLedger,
        uint256 priorLedger,
        LedgerIndex cutoffBefore) override
    {
        bool valCurrentLedger = currentLedger.isNonZero();
        bool valPriorLedger = priorLedger.isNonZero();

        LedgerToValidationCounter ret;

        ScopedLockType sl(mLock);

        forEachCurrent(true /* stale check*/, [&](auto const&, auto const& v) {
            if (v->isTrusted() && (! v->isFieldPresent (sfLedgerSequence) ||
                (v->getFieldU32 (sfLedgerSequence) >= cutoffBefore)))
            {
                // contains a live record
                bool countPreferred =
                    valCurrentLedger && (v->getLedgerHash() == currentLedger);

                if (!countPreferred &&  // allow up to one ledger slip in either
                                        // direction
                    ((valCurrentLedger && v->isPreviousHash(currentLedger)) ||
                     (valPriorLedger && (v->getLedgerHash() == priorLedger))))
                {
                    countPreferred = true;
                    JLOG(j_.trace()) << "Counting for " << currentLedger
                                     << " not " << v->getLedgerHash();
                }

                ValidationCounter& p = countPreferred ? ret[currentLedger]
                                                      : ret[v->getLedgerHash()];
                ++(p.first);
                auto ni = v->getNodeID();

                if (ni > p.second)
                    p.second = ni;
            }
        });

        return ret;
    }

    void flush () override
    {
        bool anyNew = false;

        JLOG (j_.info()) << "Flushing validations";
        ScopedLockType sl (mLock);
        for (auto& it: mCurrentValidations)
        {
            mStaleValidations.push_back (it.second);

            anyNew = true;
        }
        mCurrentValidations.clear ();

        if (anyNew)
            condWrite ();

        while (mWriting)
        {
            ScopedUnlockType sul (mLock);
            std::this_thread::sleep_for (std::chrono::milliseconds (100));
        }

        JLOG (j_.debug()) << "Validations flushed";
    }

    void condWrite ()
    {
        if (mWriting)
            return;

        mWriting = true;
        app_.getJobQueue ().addJob (
            jtWRITE, "Validations::doWrite",
            [this] (Job&) { doWrite(); });
    }

    void doWrite ()
    {
        auto event = app_.getJobQueue ().getLoadEventAP (jtDISK, "ValidationWrite");

        std::string insVal ("INSERT INTO Validations "
            "(InitialSeq, LedgerSeq, LedgerHash,NodePubKey,SignTime,RawData) "
            "VALUES (:initialSeq, :ledgerSeq, :ledgerHash,:nodePubKey,:signTime,:rawData);");
        std::string findSeq("SELECT LedgerSeq FROM Ledgers WHERE Ledgerhash=:ledgerHash;");

        ScopedLockType sl (mLock);
        assert (mWriting);

        while (!mStaleValidations.empty ())
        {
            std::vector<STValidation::pointer> vector;
            vector.reserve (512);
            mStaleValidations.swap (vector);

            {
                ScopedUnlockType sul (mLock);
                {
                    auto db = app_.getLedgerDB ().checkoutDb ();

                    Serializer s (1024);
                    soci::transaction tr(*db);
                    for (auto it: vector)
                    {
                        s.erase ();
                        it->add (s);

                        auto const ledgerHash = to_string(it->getLedgerHash());

                        boost::optional<std::uint64_t> ledgerSeq;
                        *db << findSeq, soci::use(ledgerHash),
                            soci::into(ledgerSeq);

                        auto const initialSeq = ledgerSeq.value_or(
                            app_.getLedgerMaster().getCurrentLedgerIndex());
                        auto const nodePubKey = toBase58(
                            TokenType::TOKEN_NODE_PUBLIC,
                            it->getSignerPublic());
                        auto const signTime =
                            it->getSignTime().time_since_epoch().count();

                        soci::blob rawData(*db);
                        rawData.append(reinterpret_cast<const char*>(
                            s.peekData().data()), s.peekData().size());
                        assert(rawData.get_len() == s.peekData().size());

                        *db <<
                            insVal,
                            soci::use(initialSeq),
                            soci::use(ledgerSeq),
                            soci::use(ledgerHash),
                            soci::use(nodePubKey),
                            soci::use(signTime),
                            soci::use(rawData);
                    }

                    tr.commit ();
                }
            }
        }

        mWriting = false;
    }

    void sweep () override
    {
        ScopedLockType sl (mLock);
        beast::expire(mValidations, expireAge);
    }
};

std::unique_ptr <Validations> make_Validations (Application& app)
{
    return std::make_unique <ValidationsImp> (app);
}

} // ripple
