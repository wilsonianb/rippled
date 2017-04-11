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

#ifndef RIPPLE_CONSENSUS_VALIDATIONS_H_INCLUDED
#define RIPPLE_CONSENSUS_VALIDATIONS_H_INCLUDED

#include <ripple/basics/Log.h>
#include <ripple/basics/UnorderedContainers.h>
#include <ripple/basics/chrono.h>
#include <ripple/beast/container/aged_container_utility.h>
#include <ripple/beast/container/aged_unordered_map.h>
#include <ripple/beast/utility/Journal.h>
#include <ripple/beast/utility/Zero.h>
#include <boost/optional.hpp>
#include <utility>
#include <vector>

namespace ripple {

/** Timing parameters to control validation staleness and expiration.
 */
struct ValidationParms
{
    /** The number of seconds a validation remains current after its ledger's
        close time.

        This is a safety to protect against very old validations and the time
        it takes to adjust the close time accuracy window.
    */
    std::chrono::seconds VALIDATION_CURRENT_WALL = std::chrono::minutes{5};

    /** Duration a validation remains current after first observed.

        The number of seconds a validation remains current after the time we
        first saw it. This provides faster recovery in very rare cases where the
        number of validations produced by the network is lower than normal
    */
    std::chrono::seconds VALIDATION_CURRENT_LOCAL = std::chrono::minutes{3};

    /** Duration pre-close in which validations are acceptable.

        The number of seconds before a close time that we consider a validation
        acceptable. This protects against extreme clock errors
    */
    std::chrono::seconds VALIDATION_CURRENT_EARLY = std::chrono::minutes{3};

    /** Duration a set of validations for a given ledger hash remain valid

        The number of seconds before a set of validations for a given ledger
        hash can expire.  This keeps validations for recent ledgers available
        for a reasonable interval.
    */
    std::chrono::seconds VALIDATION_SET_EXPIRES = std::chrono::minutes{10};
};

/** Whether a validation is still current

    Determines whether a validation can still be considered the current
    validation from a node based on when it was signed by that node and first
    seen by this node.

    @param p ValidationParms with timing parameters
    @param now Current time
    @param signTime When the validation was signed
    @param seenTime When the validation was first seen locally
*/
inline bool
isCurrent(
    ValidationParms const& p,
    NetClock::time_point now,
    NetClock::time_point signTime,
    NetClock::time_point seenTime)
{
    // Because this can be called on untrusted, possibly
    // malicious validations, we do our math in a way
    // that avoids any chance of overflowing or underflowing
    // the signing time.

    return (signTime > (now - p.VALIDATION_CURRENT_EARLY)) &&
        (signTime < (now + p.VALIDATION_CURRENT_WALL)) &&
        ((seenTime == NetClock::time_point{}) ||
         (seenTime < (now + p.VALIDATION_CURRENT_LOCAL)));
}

/** Maintains current and recent ledger validations.

    Manages storage and queries related to validations received on the network.
    Stores the most current validation from nodes and sets of recent
    validations grouped by ledger identifier.

    Stored validations are not necessarily from trusted nodes, so clients
    and implementations should take care to use `trusted` member functions or
    check the validation's trusted status.

    This class uses CRTP to allow adapting for specific applications. Below
    is a set of stubs illustrating the required type interface.


    @code

    // Identifier types that should be equality-comparable and copyable
    struct LedgerID;
    struct NodeID;
    struct NodeKey;

    struct Validation
    {
        // Ledger ID associated with this validation
        LedgerID ledgerID() const;

        // Optional sequence number of validation's ledger
        boost::optional<std::size_t> seq() const

        // When the validation was signed
        NetClock::time_point signTime() const;

        // When the validation was first observed by this node
        NetClock::time_point seenTime() const;

        // Signing key of node that published the validation
        NodeKey key() const;

        // Identifier of node that published the validaton
        NodeID nodeID() const;

        // Whether the publishing node was trusted at the time the validation
        // arrived
        bool trusted() const;

        // Set the previous validation ledger from this publishing node that this
        // validation replaced
        void setPreviousLedgerID(LedgerID &);

        // Check if this validation had the given ledger ID as its prior ledger
        bool isPreviousLedgerID(LedgerID const& ) const;

        // ... implementation specific
    };

    class Derived : public Validations<Derived, Validation>
    {
        Derived(ValidationParms const & p, clock_type & c, ...)
            : Validations(p, c), ...

        // Handle a newly stale validation
        void onStale(Validations && );

        // ... implementation specific
    };
    @endcode

    @tparam Derived Provides functions conforming to the CRTP interface
    @tparam Validation Conforming type representing a ledger validation

*/
template <class Derived, class Validation>
class Validations
{
    template <typename T>
    using decay_result_t = std::decay_t<std::result_of_t<T>>;

    using LedgerID =
        decay_result_t<decltype (&Validation::ledgerID)(Validation)>;
    using NodeKey = decay_result_t<decltype (&Validation::key)(Validation)>;
    using NodeID = decay_result_t<decltype (&Validation::nodeID)(Validation)>;
    using ValidationMap = hash_map<NodeKey, Validation>;

    //! The latest validation from each node
    ValidationMap current_;

    //! Recent validations from nodes, indexed by ledger identifier
    beast::aged_unordered_map<
        LedgerID,
        ValidationMap,
        std::chrono::steady_clock,
        beast::uhash<>>
        byLedger_;

    //! Parameters to determine validation staleness
    ValidationParms parms_;

    //! @return The Derived class that implements the CRTP requirements.
    Derived&
    impl()
    {
        return static_cast<Derived&>(*this);
    }

protected:
    /** Iterate current validations.

        Iterate current validations, optionally removing any stale validations
        if a time is specified

        @param t (Optional) Time used to determine staleness
        @param f Callable with signature (NodeKey const &, Validations const &)

        @note This is protected since the implementations/clients primarily
              iterate trusted validations, but the iteration logic is needed by
              the currentKeys member function to iterate all validation keys.

    */
    template <class F>
    void
    current(boost::optional<NetClock::time_point> t, F&& f)
    {
        auto it = current_.begin();
        while (it != current_.end())
        {
            // Check for staleness, if time specified
            if (t &&
                !isCurrent(
                    parms_, *t, it->second.signTime(), it->second.seenTime()))
            {
                // contains a stale record
                impl().onStale(std::move(it->second));
                it = current_.erase(it);
            }
            else
            {
                auto cit = typename ValidationMap::const_iterator{it};
                // contains a live record
                f(cit->first, cit->second);
                ++it;
            }
        }
    }

    /** Return set of validations for a ledger

        Returns the set of validations for a ledger.
        @param ledgerID The identifier of the ledger
        @return A pointer to the set of validations, nullptr if none exist.
    */
    ValidationMap const*
    byLedger(LedgerID const& ledgerID)
    {
        auto it = byLedger_.find(ledgerID);
        if (it != byLedger_.end())
        {
            // Update set time since it is being used
            byLedger_.touch(it);
            return &(it->second);
        }
        return nullptr;
    }

    //! Return the validation timing parameters
    ValidationParms const&
    parms() const
    {
        return parms_;
    }

    //! Flush all current validations into the callback
    //! @param f Callable with signature (Validation && v)
    template <class F>
    void
    flush(F && f)
    {
        for (auto& it : current_)
        {
            f(std::move(it.second));
        }
        current_.clear();
    }

public:
    /** Constructor

        @param p ValidationParms to control staleness/expiration of validaitons
        @param c Clock to use for expiring validations stored by ledger
    */
    Validations(
        ValidationParms const& p,
        beast::abstract_clock<std::chrono::steady_clock>& c)
        : byLedger_(c), parms_(p)
    {
    }

    /** Result of adding a new validation
     */
    enum class AddOutcome {
        current,  //< This was a new validation and was added
        repeat,   //< Already had this validation
        stale,    //< Not current or was older than current from this node
        sameSeq,  //< Had a validation with same sequence number
    };

    /** Add a new validation

        Attempt to add a new validation.

        @param t Current time
        @param key The NodeKey to use for the validation
        @param val The validation to store
        @return The outcome of the attempt

        @note The provided key may differ from the validation's
              key() member since we might be storing by master key and the
              validation might be signed by a temporary or rotating key.

    */
    AddOutcome
    add(NetClock::time_point t, NodeKey const& key, Validation const& val)
    {
        if (!isCurrent(parms_, t, val.signTime(), val.seenTime()))
            return AddOutcome::stale;

        auto const& id = val.ledgerID();

        if (!byLedger_[id].emplace(key, val).second)
            return AddOutcome::repeat;

        AddOutcome result = AddOutcome::current;

        // Attempt to insert
        auto ins = current_.emplace(key, val);

        if (!ins.second)
        {
            // previous validation existed, consider updating
            auto& oldVal = ins.first->second;

            auto const oldSeq = oldVal.seq();
            auto const newSeq = val.seq();

            // Sequence of 0 indicates a missing sequence number
            if (oldSeq && newSeq && oldSeq == newSeq)
            {
                result = AddOutcome::sameSeq;

                // Remove current validation from the ledger set
                // for the revoked signing key
                if (val.key() != oldVal.key())
                {
                    auto set = byLedger_.find(oldVal.ledgerID());
                    if (set != byLedger_.end())
                    {
                        set->second.erase(key);
                        // Erase the set if it is now empty
                        if (set->second.empty())
                            byLedger_.erase(set);
                    }
                }
            }

            if (val.signTime() > oldVal.signTime() || val.key() != oldVal.key())
            {
                // This is either a newer validation or a new signing key
                auto const oldID = oldVal.ledgerID();
                // Allow impl to take over oldVal
                impl().onStale(std::move(oldVal));
                // Replace old val in the map and set the previous ledger ID
                ins.first->second = val;
                ins.first->second.setPreviousLedgerID(oldID);
            }
            else
            {
                // We already have a newer validation from this source
                result = AddOutcome::stale;
            }
        }

        return result;
    }

    /** Expire old validation sets

        Remove validation sets that were accessed more than
        VALIDATION_SET_EXPIRES ago.
    */
    void
    expire()
    {
        beast::expire(byLedger_, parms_.VALIDATION_SET_EXPIRES);
    }

    struct ValidationCounts
    {
        //! The number of trusted validations
        std::size_t count;
        //! The highest trusting node ID
        NodeID highNode;
    };

    /** Distribution of current trusted validations

        Calculates the distribution of current validations but allows
        ledgers one away from the current ledger to count as the current.

        @param t Current time used to determine ledger staleness
        @param currentLedger The identifier of the ledger we believe is current
        @param priorLedger The identifier of our previous current ledger
        @param cutoffBefore Ignore ledgers with sequence number before this
        @param j Journal for logging
    */
    hash_map<LedgerID, ValidationCounts>
    currentTrustedDistribution(
        NetClock::time_point t,
        LedgerID const& currentLedger,
        LedgerID const& priorLedger,
        std::size_t cutoffBefore,
        beast::Journal& j)
    {
        bool valCurrentLedger = currentLedger != beast::zero;
        bool valPriorLedger = priorLedger != beast::zero;

        hash_map<LedgerID, ValidationCounts> ret;

        current(t, [&](auto const&, auto const& v) {

            if (!v.trusted())
                return;

            std::size_t seq = v.seq();
            if ((seq == 0) || (seq >= cutoffBefore))
            {
                // contains a live record
                bool countPreferred =
                    valCurrentLedger && (v.ledgerID() == currentLedger);

                if (!countPreferred &&  // allow up to one ledger slip in
                                        // either direction
                    ((valCurrentLedger &&
                      v.isPreviousLedgerID(currentLedger)) ||
                     (valPriorLedger && (v.ledgerID() == priorLedger))))
                {
                    countPreferred = true;
                    JLOG(j.trace()) << "Counting for " << currentLedger
                                    << " not " << v.ledgerID();
                }

                auto& p =
                    countPreferred ? ret[currentLedger] : ret[v.ledgerID()];
                ++(p.count);

                NodeID ni = v.nodeID();
                if (ni > p.highNode)
                    p.highNode = ni;
            }
        });

        return ret;
    }

    /** Count the number of current trusted validators working on the next
        ledger.

        Counts the number of current trusted validations that replaced the
        provided ledger.  Does not check or update staleness of the validations.

        @param ledgerID The identifier of the preceededing ledger of interest
        @return The number of current trusted validators with ledgerID as the
                prior ledger.
    */
    std::size_t
    getNodesAfter(LedgerID const& ledgerID)
    {
        std::size_t count = 0;

        current(boost::none, [&](auto const&, auto const& v) {
            if (v.trusted() && v.isPreviousLedgerID(ledgerID))
                ++count;
        });
        return count;
    }

    /** Count the number of trusted validations for the given ledger

        @param ledgerID The identifier of ledger of interest
        @return The number of trusted validations
    */
    std::size_t
    numTrustedForLedger(LedgerID const& ledgerID)
    {
        std::size_t count = 0;
        if (auto map = byLedger(ledgerID))
        {
            for (auto const& it : *map)
            {
                if (it.second.trusted())
                    ++count;
            }
        }
        return count;
    }
};
}
#endif
