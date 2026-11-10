//! nftables rules and their ordered packet-processing expressions.
//!
//! These types describe rules locally. Constructing a rule does not install it
//! in the kernel or modify the chain it borrows.
//!
//! # References
//!
//! - [Kernel rule attributes](https://docs.kernel.org/netlink/specs/nftables.html#rule-attrs)
//! - [Kernel expression attributes](https://docs.kernel.org/netlink/specs/nftables.html#expr-attrs)

use crate::chain::Chain;

/// An ordered sequence of expressions belonging to an nftables chain.
#[must_use = "a rule must be queued in a batch to take effect"]
#[derive(Debug, Clone)]
pub struct Rule<'a> {
    /// The borrowed parent chain.
    pub chain: &'a Chain,
    /// Operations evaluated in order.
    pub expressions: Vec<Expression>,
}

impl<'a> Rule<'a> {
    /// Creates an empty rule borrowing its parent chain.
    pub fn new(chain: &'a Chain) -> Self {
        Self {
            chain,
            expressions: Vec::new(),
        }
    }

    /// Appends a packet and byte counter.
    pub fn counter(mut self) -> Self {
        self.expressions.push(Expression::Counter);
        self
    }

    /// Appends a verdict. Expressions after it will not be evaluated.
    pub fn verdict(mut self, verdict: Verdict) -> Self {
        self.expressions.push(Expression::Verdict(verdict));
        self
    }
}

/// An operation evaluated in order within a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// Count packets and bytes, then continue evaluation.
    Counter,
    /// Issue a verdict that ends evaluation of the current chain.
    Verdict(Verdict),
}

/// A packet verdict issued explicitly by a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Accept in this chain; later processing may still drop the packet.
    Accept,
    /// Discard the packet and end evaluation.
    Drop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Table, TableFamily, TableFlags};

    fn chain() -> Chain {
        Chain {
            name: "services".into(),
            table: Table {
                name: "filter".into(),
                family: TableFamily::IPV6,
                flags: TableFlags::DORMANT,
                use_count: 0,
                owner: None,
            },
            hooknum: None,
            priority: None,
            chain_type: None,
            policy: None,
            device: None,
        }
    }

    #[test]
    fn rule_new_borrows_parent_chain_and_starts_without_expressions() {
        let chain = chain();
        let rule = Rule::new(&chain);
        assert!(std::ptr::eq(rule.chain, &chain));
        assert_eq!(rule.chain.name, "services");
        assert_eq!(rule.chain.table.name, "filter");
        assert_eq!(rule.chain.table.family, TableFamily::IPV6);
        assert!(rule.expressions.is_empty());
    }

    #[test]
    fn rule_counter_preserves_repeated_expressions() {
        let chain = chain();
        let rule = Rule::new(&chain).counter().counter();
        assert_eq!(rule.expressions, vec![Expression::Counter, Expression::Counter]);
    }

    #[test]
    fn rule_verdict_supports_accept_and_drop() {
        let chain = chain();
        for verdict in [Verdict::Accept, Verdict::Drop] {
            let rule = Rule::new(&chain).verdict(verdict);
            assert_eq!(rule.expressions, vec![Expression::Verdict(verdict)]);
        }
    }

    #[test]
    fn rule_fluent_methods_preserve_expression_order() {
        let chain = chain();
        let rule = Rule::new(&chain).counter().counter().verdict(Verdict::Drop);
        assert_eq!(
            rule.expressions,
            vec![
                Expression::Counter,
                Expression::Counter,
                Expression::Verdict(Verdict::Drop)
            ],
        );
    }

    #[test]
    fn rule_clone_preserves_parent_borrow_and_has_independent_expressions() {
        let chain = chain();
        let original = Rule::new(&chain).counter();
        let copy = original.clone().verdict(Verdict::Accept);
        assert!(std::ptr::eq(original.chain, copy.chain));
        assert_eq!(original.expressions, vec![Expression::Counter]);
        assert_eq!(
            copy.expressions,
            vec![Expression::Counter, Expression::Verdict(Verdict::Accept)]
        );
    }
}
