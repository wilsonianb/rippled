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

#ifndef RIPPLE_APP_CONSENSUSS_VALIDATIONS_H_INCLUDED
#define RIPPLE_APP_CONSENSUSS_VALIDATIONS_H_INCLUDED

#include <ripple/basics/ScopedLock.h>
#include <ripple/consensus/Validations.h>
#include <ripple/protocol/Protocol.h>
#include <ripple/protocol/STValidation.h>
#include <vector>

namespace ripple {

class Application;

/** Wrapper over STValidation for generic Validation code

    Wraps an STValidation::pointer for compatiblity with the generic validation
    code.
*/
struct RCLValidation
{
    /** Constructor

        @param v The validation to wrap.
    */
    RCLValidation(STValidation::pointer const& v) : val_{v}
    {
    }

    uint256
    ledgerID() const
    {
        return val_->getLedgerHash();
    }

    std::size_t
    seq() const
    {
        return val_->getFieldU32(sfLedgerSequence);
    }

    NetClock::time_point
    signTime() const
    {
        return val_->getSignTime();
    }

    NetClock::time_point
    seenTime() const
    {
        return val_->getSeenTime();
    }

    PublicKey
    key() const
    {
        return val_->getSignerPublic();
    }

    NodeID
    nodeID() const
    {
        return val_->getNodeID();
    }

    bool
    trusted() const
    {
        return val_->isTrusted();
    }

    void
    setPreviousLedgerID(uint256 const& hash)
    {
        val_->setPreviousHash(hash);
    }

    bool
    isPreviousLedgerID(uint256 const& hash) const
    {
        return val_->isPreviousHash(hash);
    }

    STValidation::pointer val_;
};

/** Adapts the generic Validations code for use by RCL

    Stores both listed and trusted validations.  Listed validations are from
    nodes which are in a published lists, but which are not in this node's
    current trusted list.  Trusted validations are validations received from
    nodes that are in the trusted list (UNL) at the time the validation arrives.

    Implements the CRTP type requirements of Validations by saving
    stale validations to the sqlite DB.  The generic Validations class does
    not internally lock to manage concurrent access, so this class acquires the
    lock before all calls to the base class.

*/
class RCLValidations : public Validations<RCLValidations, RCLValidation>
{
    friend class Validations<RCLValidations, RCLValidation>;

    using LockType = std::mutex;
    using ScopedLockType = std::lock_guard<LockType>;
    using ScopedUnlockType = GenericScopedUnlock<LockType>;

    Application& app_;
    std::mutex mutable lock_;
    std::vector<STValidation::pointer> staleValidations_;
    bool writing_ = false;

    beast::Journal j_;

    NetClock::time_point
    now() const;

    //! Write stale validations to the DB
    //! NOTE: doWrite() must be called with mLock *locked*.  The passed
    //! ScopedLockType& acts as a reminder to future maintainers.
    void
    doWrite(ScopedLockType &);

    /** Callback to handle a validation that is now stale.

        @param v The newly stale validation

        @note onStale is only called by the CRTP base Validations class.  Since
              the lock_ must be acquired prior to all calls of that class, it
              remains locked for any calls of onStale.
    */
    void
    onStale(RCLValidation&& v);

public:
    /** Constructor

        @param app Application object
    */
    RCLValidations(Application& app);

    /** Attempt to add a validation

        Attempt to add a validation
        @param val The validation to add
        @param source Name associated with validation used in logging

        @return Whether the validation should be relayed
    */
    bool
    add(STValidation::ref val, std::string const& source);

    /** @return Whether the given validation is current
     */
    bool isCurrent(STValidation::ref val);

    /**  Get set of trusted validationss associated with a given ledger

         @param ledger Ledger hash of interest
         @return Trusted validations associated with ledger
    */
    std::vector<STValidation::pointer>
    getTrustedForLedger(uint256 const& ledger);

    /** Get number of trusted validations associated with a given ledger

        @param ledger Ledger hash of interest
        @return Number of trusted validations associated with ledger
    */
    std::size_t
    numTrustedForLedger(uint256 const& ledger);

    /** Returns fees reported by trusted validators in the given ledger

        @param ledger Ledger hash of interest
        @param base The fee to report if not present in the validation
        @return Vector of fees
    */
    std::vector<std::uint64_t>
    fees(uint256 const& ledger, std::uint64_t base);

    /** Return the times of all validations for a particular ledger hash.

        @param ledger Ledger has of interest
        @return Vector of times
    */
    std::vector<NetClock::time_point>
    getValidationTimes(uint256 const& ledger);

    //! @ref Validations::getNodesAfter
    std::size_t
    getNodesAfter(uint256 const& ledger);

    //! @ref Validations::currentTrustedDistribution
    hash_map<uint256, ValidationCounts>
    currentTrustedDistribution(
        uint256 const & currentLedger,
        uint256 const & previousLedger,
        LedgerIndex cutoffBefore);

    /** @return set of public keys for current listed or trusted validations
     */
    hash_set<PublicKey>
    getCurrentPublicKeys();

    /** @return list of current trusted validations */
    std::vector<STValidation::pointer>
    currentTrusted();

    /** Flush all current validations */
    void
    flush();

    /** Sweep expired validation sets */
    void
    sweep();
};

}  // ripple

#endif
