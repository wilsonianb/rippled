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
#include <ripple/app/consensus/RCLValidations.h>
#include <ripple/app/ledger/LedgerMaster.h>
#include <ripple/app/main/Application.h>
#include <ripple/app/misc/NetworkOPs.h>
#include <ripple/app/misc/ValidatorList.h>
#include <ripple/basics/Log.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/basics/chrono.h>
#include <ripple/consensus/LedgerTiming.h>
#include <ripple/core/DatabaseCon.h>
#include <ripple/core/JobQueue.h>
#include <ripple/core/TimeKeeper.h>
#include <memory>
#include <mutex>
#include <thread>

namespace ripple {

RCLValidations::RCLValidations(Application& app)
    : Validations{ValidationParms{}, stopwatch()}
    , app_(app)
    , j_(app.journal("Validations"))
{
    staleValidations_.reserve(512);
}

NetClock::time_point
RCLValidations::now() const
{
    return app_.timeKeeper().closeTime();
}

bool
RCLValidations::add(STValidation::ref val, std::string const& source)
{
    PublicKey const& signer = val->getSignerPublic();
    uint256 const& hash = val->getLedgerHash();

    // Ensure validation is marked as trusted if signer currently trusted
    boost::optional<PublicKey> pubKey = app_.validators().getTrustedKey(signer);
    if (!val->isTrusted() && pubKey)
        val->setTrusted();

    if (!val->isTrusted())
    {
        JLOG(j_.trace()) << "Node "
                         << toBase58(TokenType::TOKEN_NODE_PUBLIC, signer)
                         << " not in UNL st="
                         << val->getSignTime().time_since_epoch().count()
                         << ", hash=" << hash
                         << ", shash=" << val->getSigningHash()
                         << " src=" << source;
    }

    // If not currently trusted, see if signer is currently listed
    if (!pubKey)
        pubKey = app_.validators().getListedKey(signer);

    bool currVal = isCurrent(val);
    // only add trusted or listed
    if (currVal && (val->isTrusted() || pubKey))
    {
        ScopedLockType sl(lock_);
        Validations::AddOutcome res = Validations::add(now(), *pubKey, val);

        // This is a duplicate validation
        if (res == AddOutcome::repeat)
            return false;
        // This validation replaced a prior one with the same sequence number
        if (res == AddOutcome::sameSeq)
        {
            auto const seq = val->getFieldU32(sfLedgerSequence);
            JLOG(j_.warn())
                << "Trusted node "
                << toBase58(TokenType::TOKEN_NODE_PUBLIC, *pubKey)
                << " published multiple validations for ledger " << seq;
        }

        currVal = res == AddOutcome::current;
    }

    JLOG(j_.debug()) << "Val for " << hash << " from "
                     << toBase58(TokenType::TOKEN_NODE_PUBLIC, signer)
                     << " added "
                     << (val->isTrusted() ? "trusted/" : "UNtrusted/")
                     << (currVal ? "current" : "stale");

    if (val->isTrusted() && currVal)
    {
        app_.getLedgerMaster().checkAccept(
            hash, val->getFieldU32(sfLedgerSequence));
        return true;
    }

    // FIXME: This never forwards untrusted validations, from @JoelKatz:
    // The idea was that we would have a certain number of validation slots with
    // priority going to validators we trusted. Remaining slots might be
    // allocated to validators that were listed by publishers we trusted but
    // that we didn't choose to trust. The shorter term plan was just to forward
    // untrusted validations if peers wanted them or if we had the
    // ability/bandwidth to. None of that was implemented.
    return false;
}

bool
RCLValidations::isCurrent(STValidation::ref val)
{
    using ripple::isCurrent;
    return isCurrent(parms(), now(), val->getSignTime(), val->getSeenTime());
}

std::vector<STValidation::pointer>
RCLValidations::getTrustedForLedger(uint256 const& ledger)
{
    std::vector<STValidation::pointer> res;
    {
        ScopedLockType sl(lock_);
        Validations::byLedger(
            ledger, [&](PublicKey const&, RCLValidation const& v) {
                if (v.trusted())
                    res.emplace_back(v.val_);
            });
    }
    return res;
}

std::vector<NetClock::time_point>
RCLValidations::getValidationTimes(uint256 const& ledger)
{
    std::vector<NetClock::time_point> times;
    {
        ScopedLockType sl(lock_);
        Validations::byLedger(
            ledger, [&](PublicKey const&, RCLValidation const& v) {
                if (v.trusted())
                    times.emplace_back(v.signTime());
            });
    }
    return times;
}

std::size_t
RCLValidations::numTrustedForLedger(uint256 const& ledger)
{
    ScopedLockType sl(lock_);
    return Validations::numTrustedForLedger(ledger);
}

std::vector<std::uint64_t>
RCLValidations::fees(uint256 const& ledger, std::uint64_t base)
{
    std::vector<std::uint64_t> result;
    {
        ScopedLockType sl(lock_);

        Validations::byLedger(
            ledger, [&](PublicKey const&, RCLValidation const& v) {
                if (v.trusted())
                {
                    STValidation::pointer const& val = v.val_;
                    if (val->isFieldPresent(sfLoadFee))
                        result.push_back(val->getFieldU32(sfLoadFee));
                    else
                        result.push_back(base);
                }
            });
    }

    return result;
}

std::size_t
RCLValidations::getNodesAfter(uint256 const& ledger)
{
    ScopedLockType sl(lock_);
    return Validations::getNodesAfter(ledger);
}

std::vector<STValidation::pointer>
RCLValidations::currentTrusted()
{
    std::vector<STValidation::pointer> ret;

    ScopedLockType sl(lock_);

    Validations::current(now(), [&](PublicKey const&, RCLValidation const& v) {
        if (v.trusted())
            ret.push_back(v.val_);
    });
    return ret;
}

hash_set<PublicKey>
RCLValidations::getCurrentPublicKeys()
{
    hash_set<PublicKey> ret;

    ScopedLockType sl(lock_);
    Validations::current(
        now(), [&](PublicKey const& k, RCLValidation const&) { ret.insert(k); });

    return ret;
}

auto
RCLValidations::currentTrustedDistribution(
    uint256 const& currentLedger,
    uint256 const& priorLedger,
    LedgerIndex cutoffBefore) -> hash_map<uint256, ValidationCounts>
{
    ScopedLockType sl(lock_);

    return Validations::currentTrustedDistribution(
        now(), currentLedger, priorLedger, cutoffBefore, j_);
}

void
RCLValidations::onStale(RCLValidation&& v)
{
    staleValidations_.emplace_back(std::move(v.val_));
    if (writing_)
        return;

    writing_ = true;
    app_.getJobQueue().addJob(jtWRITE, "Validations::doWrite", [this](Job&) {

        auto event =
            app_.getJobQueue().getLoadEventAP(jtDISK, "ValidationWrite");
        ScopedLockType sl(lock_);
        doWrite(sl);
    });
}

void
RCLValidations::flush()
{
    JLOG(j_.info()) << "Flushing validations";
    bool anyNew = false;
    {
        ScopedLockType sl(lock_);

        Validations::flush([&](RCLValidation&& v) {
            staleValidations_.emplace_back(std::move(v.val_));
            anyNew = true;
        });

        // If there isn't a write in progress already, then write to the
        // database synchronously.
        if (anyNew && !writing_)
        {
            writing_ = true;
            doWrite(sl);
        }

        // Handle the case where flush() is called while a queuedWrite
        // is already in progress.
        while (writing_)
        {
            ScopedUnlockType sul(lock_);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    JLOG(j_.debug()) << "Validations flushed";
}

void
RCLValidations::sweep()
{
    ScopedLockType sl(lock_);
    Validations::expire();
}

// NOTE: doWrite() must be called with mLock *locked*.  The passed
// ScopedLockType& acts as a reminder to future maintainers.
void
RCLValidations::doWrite(ScopedLockType&)
{
    std::string insVal(
        "INSERT INTO Validations "
        "(InitialSeq, LedgerSeq, LedgerHash,NodePubKey,SignTime,RawData) "
        "VALUES (:initialSeq, :ledgerSeq, "
        ":ledgerHash,:nodePubKey,:signTime,:rawData);");
    std::string findSeq(
        "SELECT LedgerSeq FROM Ledgers WHERE Ledgerhash=:ledgerHash;");

    assert(writing_);

    while (!staleValidations_.empty())
    {
        std::vector<STValidation::pointer> vector;
        vector.reserve(512);
        staleValidations_.swap(vector);

        {
            ScopedUnlockType sul(lock_);
            {
                auto db = app_.getLedgerDB().checkoutDb();

                Serializer s(1024);
                soci::transaction tr(*db);
                for (auto it : vector)
                {
                    s.erase();
                    it->add(s);

                    auto const ledgerHash = to_string(it->getLedgerHash());

                    boost::optional<std::uint64_t> ledgerSeq;
                    *db << findSeq, soci::use(ledgerHash),
                        soci::into(ledgerSeq);

                    auto const initialSeq = ledgerSeq.value_or(
                        app_.getLedgerMaster().getCurrentLedgerIndex());
                    auto const nodePubKey = toBase58(
                        TokenType::TOKEN_NODE_PUBLIC, it->getSignerPublic());
                    auto const signTime =
                        it->getSignTime().time_since_epoch().count();

                    soci::blob rawData(*db);
                    rawData.append(
                        reinterpret_cast<const char*>(s.peekData().data()),
                        s.peekData().size());
                    assert(rawData.get_len() == s.peekData().size());

                    *db << insVal, soci::use(initialSeq), soci::use(ledgerSeq),
                        soci::use(ledgerHash), soci::use(nodePubKey),
                        soci::use(signTime), soci::use(rawData);
                }

                tr.commit();
            }
        }
    }

    writing_ = false;
}

}  // namespace ripple
