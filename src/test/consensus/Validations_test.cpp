//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012-2017 Ripple Labs Inc.

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
#include <ripple/beast/clock/manual_clock.h>
#include <ripple/beast/unit_test.h>
#include <ripple/consensus/Validations.h>

#include <type_traits>
#include <vector>


namespace ripple {
namespace test {

class Validations_test : public beast::unit_test::suite
{
    using clock_type = beast::abstract_clock<std::chrono::steady_clock> const;
    //--------------------------------------------------------------------------
    // Basic type wrappers for validation types

    // Represents a ledger sequence number
    struct Seq
    {
        explicit Seq(std::size_t sIn) : s{sIn}
        {
        }

        Seq() : s{0}
        {
        }

        operator std::size_t() const
        {
            return s;
        }

        std::size_t s;
    };

    // Represents a unique ledger identifier
    struct ID
    {
        explicit ID(std::size_t idIn) : id{idIn}
        {
        }

        ID() : id{0}
        {
        }

        int
        signum() const
        {
            return id == 0 ? 0 : 1;
        }

        operator std::size_t() const
        {
            return id;
        }

        template <class Hasher>
        friend void
        hash_append(Hasher& h, ID const& id)
        {
            using beast::hash_append;
            hash_append(h, id.id);
        }

        std::size_t id;
    };

    class Node;

    // Basic implementation of the requirements of Validation in the generic
    // Validations class
    class Validation
    {
        friend class Node;

        ID ledgerID_ = ID{0};
        Seq seq_ = Seq{0};
        NetClock::time_point signTime_;
        NetClock::time_point seenTime_;
        std::string key_;
        std::size_t nodeID_ = 0;
        bool trusted_ = true;
        std::size_t prevID_ = 0;

    public:
        ID
        ledgerID() const
        {
            return ledgerID_;
        }

        Seq
        seq() const
        {
            return seq_;
        }

        NetClock::time_point
        signTime() const
        {
            return signTime_;
        }

        NetClock::time_point
        seenTime() const
        {
            return seenTime_;
        }

        std::string
        key() const
        {
            return key_;
        }

        std::size_t
        nodeID() const
        {
            return nodeID_;
        }

        bool
        trusted() const
        {
            return trusted_;
        }

        void
        setPreviousLedgerID(std::size_t const& prevID)
        {
            prevID_ = prevID;
        }

        bool
        isPreviousLedgerID(std::size_t const& prevID) const
        {
            return prevID_ == prevID;
        }
    };


    // Represents a node that can issue validations
    class Node
    {
        clock_type const& c_;
        std::size_t nodeID_;
        bool trusted_ = true;
        std::size_t signIdx_ = 0;

    public:
        Node(std::size_t nodeID, clock_type const& c) : c_(c), nodeID_(nodeID)
        {
        }

        void
        untrust()
        {
            trusted_ = false;
        }

        void
        trust()
        {
            trusted_ = true;
        }

        std::size_t
        nodeID() const
        {
            return nodeID_;
        }

        void
        advanceKey()
        {
            signIdx_++;
        }

        std::string
        masterKey() const
        {
            return std::to_string(nodeID_);
        }

        std::string
        currKey() const
        {
            return masterKey() + "_" + std::to_string(signIdx_);
        }

        NetClock::time_point
        now() const
        {
            // We don't care about the actual epochs, but do want the
            // generated NetClock time to be well past its epoch to ensure
            // any subtractions are positive
            using namespace std::chrono;
            return NetClock::time_point(duration_cast<NetClock::duration>(
                c_.now().time_since_epoch() + 86400s));
        }

        // Issue a new validation with given sequence number and id and
        // with signing and seen times offset from the common clock
        Validation
        validation(
            Seq seq,
            ID i,
            NetClock::duration signOffset,
            NetClock::duration seenOffset) const
        {
            Validation v;
            v.seq_ = seq;
            v.ledgerID_ = i;

            v.signTime_ = now() + signOffset;
            v.seenTime_ = now() + seenOffset;

            v.nodeID_ = nodeID_;
            v.key_ = currKey();
            v.trusted_ = trusted_;

            return v;
        }

        // Issue a new validation with the given sequence number and id
        Validation
        validation(Seq seq, ID i) const
        {
            return validation(
                seq, i, NetClock::duration{0}, NetClock::duration{0});
        }
    };

    // Implements the Validations CRTP requirements
    struct TestValidations : Validations<TestValidations, Validation>
    {
        std::vector<Validation> stale;

        TestValidations(
            ValidationParms const& p,
            beast::abstract_clock<std::chrono::steady_clock>& c)
            : Validations(p, c)
        {
        }

        // Implements the CRTP onStale callback
        void
        onStale(Validation&& v)
        {
            stale.emplace_back(std::move(v));
        }

        using Validations::add;

        // Helper to add an existing validation
        AddOutcome
        add(Node const& n, Validation const& v)
        {
            return add(n.now(), n.masterKey(), v);
        }

        // Helper to directly create the validation
        template <class... Ts>
        std::enable_if_t<(sizeof...(Ts) > 1), AddOutcome>
        add(Node const& n, Ts && ... ts)
        {
            return add(n, n.validation(std::forward<Ts>(ts)...));
        }

        // Helper to walk over the current validations
        template <class F>
        void
        current(NetClock::time_point now, F&& f)
        {
            return Validations::current(
                now, [&](auto const& , auto const& v) { return f(v); });
        }

        // Helper to return the set of ledgers indexed by ledger ID
        auto
        by(ID id)
        {
            return Validations::byLedger(id);
        }
    };

    // Hoist enum
    using AddOutcome = TestValidations::AddOutcome;

    void
    testAddValidation()
    {
        // Test adding current,stale,repeat,sameSeq validations
        using namespace std::chrono_literals;

        ValidationParms p;
        beast::manual_clock<std::chrono::steady_clock> clock;

        TestValidations vals{p, clock};
        Node a{0, clock};

        {
            {
                auto v = a.validation(Seq{1}, ID{1});

                // Add a current validation
                BEAST_EXPECT(AddOutcome::current == vals.add(a, v));

                // Re-adding is repeat
                BEAST_EXPECT(AddOutcome::repeat == vals.add(a, v));
            }

            {
                clock.advance(1s);
                // Replace with a new validation and ensure the old one is stale
                BEAST_EXPECT(vals.stale.empty());

                BEAST_EXPECT(AddOutcome::current == vals.add(a, Seq{2}, ID{2}));

                BEAST_EXPECT(vals.stale.size() == 1);

                BEAST_EXPECT(vals.stale[0].ledgerID() == 1);
            }

            {
                // Test the node changing signing key, then reissuing a ledger

                // Confirm old ledger on hand, but not new ledger
                BEAST_EXPECT(vals.by(ID{2}));
                BEAST_EXPECT(!vals.by(ID{20}));

                a.advanceKey();

                // A new id is needed since the signing key changed
                BEAST_EXPECT(AddOutcome::sameSeq == vals.add(a, Seq{2}, ID{20}));

                BEAST_EXPECT(!vals.by(ID{2}));
                BEAST_EXPECT(vals.by(ID{20}));
            }

            {
                // Processing validations out of order should ignore the older
                clock.advance(2s);
                auto val3 = a.validation(Seq{3}, ID{3});

                clock.advance(4s);
                auto val4 = a.validation(Seq{4}, ID{4});

                BEAST_EXPECT(AddOutcome::current == vals.add(a, val4));

                BEAST_EXPECT(AddOutcome::stale == vals.add(a, val3));
            }

            {
                // Test stale on arrival validations
                clock.advance(1h);

                BEAST_EXPECT(
                    AddOutcome::stale ==
                    vals.add(a, Seq{5}, ID{5}, -p.VALIDATION_CURRENT_EARLY, 0s));

                BEAST_EXPECT(
                    AddOutcome::stale ==
                    vals.add(a, Seq{5}, ID{5}, p.VALIDATION_CURRENT_WALL, 0s));

                BEAST_EXPECT(
                    AddOutcome::stale ==
                    vals.add(a, Seq{5}, ID{5}, 0s, p.VALIDATION_CURRENT_LOCAL));
            }
        }
    }

    void
    testOnStale()
    {
        // Verify validation becomes stale based solely on time passing
        using namespace std::chrono_literals;

        ValidationParms p;
        beast::manual_clock<std::chrono::steady_clock> clock;

        TestValidations vals{p, clock};
        Node a{0, clock};

        BEAST_EXPECT(AddOutcome::current == vals.add(a, Seq{1}, ID{1}));

        BEAST_EXPECT(vals.stale.empty());

        clock.advance(p.VALIDATION_CURRENT_LOCAL);

        // trigger iteration over current
        vals.current(a.now(), [](auto const&) {});

        BEAST_EXPECT(vals.stale.size() == 1);
        BEAST_EXPECT(vals.stale[0].ledgerID() == 1);
    }

    void
    testExpire()
    {
        // Verify expiring clears out validations stored by ledger
        using namespace std::chrono_literals;

        ValidationParms p;
        beast::manual_clock<std::chrono::steady_clock> clock;

        TestValidations vals{p, clock};
        Node a{0, clock};

        BEAST_EXPECT(AddOutcome::current == vals.add(a, Seq{1}, ID{1}));
        BEAST_EXPECT(vals.by(ID{1}));
        clock.advance(p.VALIDATION_SET_EXPIRES);
        vals.expire();
        BEAST_EXPECT(!vals.by(ID{1}));
    }

    void
    testGetNodesAfter()
    {
        // Test getting number of nodes working on a validation following
        // a prescribed one
        using namespace std::chrono_literals;

        ValidationParms p;
        beast::manual_clock<std::chrono::steady_clock> clock;

        TestValidations vals{p, clock};
        Node a{0, clock}, b{1, clock}, c{2, clock}, d{3, clock};
        c.untrust();

        // first round a,b,c agree, d has differing id
        for(auto const & node : {a,b,c})
            BEAST_EXPECT(AddOutcome::current == vals.add(node, Seq{1}, ID{1}));
        BEAST_EXPECT(AddOutcome::current == vals.add(d, Seq{1}, ID{10}));

        // Nothing past ledger 1 yet
        BEAST_EXPECT(vals.getNodesAfter(ID{1}) == 0);

        clock.advance(5s);

        // a and b have the same prior id, but b has a different current id
        // c is untrusted but on the same prior id
        // d has a different prior id
        BEAST_EXPECT(AddOutcome::current == vals.add(a, Seq{2}, ID{2}));
        BEAST_EXPECT(AddOutcome::current == vals.add(b, Seq{2}, ID{20}));
        BEAST_EXPECT(AddOutcome::current == vals.add(c, Seq{2}, ID{2}));
        BEAST_EXPECT(AddOutcome::current == vals.add(d, Seq{2}, ID{2}));

        BEAST_EXPECT(vals.getNodesAfter(ID{1}) == 2);


    }

    void
    testNumTrustedForLedger()
    {
        // Test number of trusted validations for not arbitrary ledger ids
        using namespace std::chrono_literals;

        ValidationParms p;
        beast::manual_clock<std::chrono::steady_clock> clock;

        TestValidations vals{p, clock};
        Node a{0, clock}, b{1, clock}, c{2, clock};
        c.untrust();

        // first round a,b,c agree
        for(auto const & node : {a,b,c})
            BEAST_EXPECT(AddOutcome::current == vals.add(node, Seq{1}, ID{1}));


        BEAST_EXPECT(vals.numTrustedForLedger(ID{1}) == 2);

        clock.advance(5s);
        for(auto const & node : {a,b,c})
            BEAST_EXPECT(AddOutcome::current == vals.add(node, Seq{2}, ID{2}));

        BEAST_EXPECT(vals.numTrustedForLedger(ID{1}) == 2);

        BEAST_EXPECT(vals.numTrustedForLedger(ID{13}) == 0);
    }

    void
    testCurrentTrustedDistribution()
    {
        // Test the trusted distribution calculation, including ledger slips
        // and sequence cutoffs
        using namespace std::chrono_literals;

        beast::Journal j;
        ValidationParms p;
        beast::manual_clock<std::chrono::steady_clock> clock;

        TestValidations vals{p, clock};
        Node baby{0, clock}, papa{1, clock}, mama{2, clock}, goldilocks{3, clock};
        goldilocks.untrust();

        // Stagger the validations around sequence 2
        //  papa on seq 1 is behind
        //  baby on seq 2 is just right
        //  mama on seq 3 is ahead
        //  goldilocks on seq 2, but is not trusted

        for(auto const & node : {baby, papa, mama, goldilocks})
            BEAST_EXPECT(AddOutcome::current == vals.add(node, Seq{1}, ID{1}));

        clock.advance(1s);
        for(auto const & node : {baby, mama, goldilocks})
            BEAST_EXPECT(AddOutcome::current == vals.add(node, Seq{2}, ID{2}));

        clock.advance(1s);
        BEAST_EXPECT(AddOutcome::current == vals.add(mama, Seq{3}, ID{3}));


        {
            // Allow slippage that treats all trusted as the current ledger
            auto res = vals.currentTrustedDistribution(
                baby.now(),
                ID{2},  // Current ledger
                ID{1},  // Prior ledger
                Seq{0}, // No cutoff
                j);
            BEAST_EXPECT(res.size() == 1);
            BEAST_EXPECT(res[ID{2}].count == 3);
            BEAST_EXPECT(res[ID{2}].highNode == mama.nodeID());
        }

        {
            // Don't allow slippage back for prior ledger
            auto res = vals.currentTrustedDistribution(
                baby.now(),
                ID{2},  // Current ledger
                ID{0},  // No prior ledger
                Seq{0}, // No cutoff
                j);
            BEAST_EXPECT(res.size() == 2);
            BEAST_EXPECT(res[ID{2}].count == 2);
            BEAST_EXPECT(res[ID{2}].highNode == mama.nodeID());
            BEAST_EXPECT(res[ID{1}].count == 1);
            BEAST_EXPECT(res[ID{1}].highNode == papa.nodeID());
        }

        {
            // Don't allow any slips
            auto res = vals.currentTrustedDistribution(
                baby.now(),
                ID{0},  // No current ledger
                ID{0},  // No prior ledger
                Seq{0}, // No cutoff
                j);
            BEAST_EXPECT(res.size() == 3);
            BEAST_EXPECT(res[ID{1}].count == 1);
            BEAST_EXPECT(res[ID{1}].highNode == papa.nodeID());
            BEAST_EXPECT(res[ID{2}].count == 1);
            BEAST_EXPECT(res[ID{2}].highNode == baby.nodeID());
            BEAST_EXPECT(res[ID{3}].count == 1);
            BEAST_EXPECT(res[ID{3}].highNode == mama.nodeID());
        }

        {
            // Cutoff old sequence numberss
            auto res = vals.currentTrustedDistribution(
                baby.now(),
                ID{2},  // current ledger
                ID{1},  // prior ledger
                Seq{2},  // Only sequence 2 or later
                j);
            BEAST_EXPECT(res.size() == 1);
            BEAST_EXPECT(res[ID{2}].count == 2);
            BEAST_EXPECT(res[ID{2}].highNode == mama.nodeID());
        }


    }

    void
    run() override
    {
        testAddValidation();
        testOnStale();
        testExpire();
        testGetNodesAfter();
        testNumTrustedForLedger();
        testCurrentTrustedDistribution();
    }
};

BEAST_DEFINE_TESTSUITE(Validations, consensus, ripple);
}  // test
}  // ripple
