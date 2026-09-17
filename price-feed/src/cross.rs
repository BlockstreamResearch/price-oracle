use std::cmp::Ordering;

use crate::{
    price_data::PriceFeedData,
    registry::{Asset, FeedDefinition, FeedId, FeedKind, FeedRegistry},
};

/// One leg of a Cross pair's route: a Direct feed, or its reciprocal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputationPath {
    pub feed: FeedId,
    pub invert: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CrossPairError {
    #[error("cross pair {0} quotes an asset in itself")]
    SameAsset(FeedId),
    #[error("no route of direct feeds joins the assets of cross pair {0}")]
    NoRoute(FeedId),
}

/// Every simple route of Direct feeds from the pair's base to its quote, fewest
/// legs first and equal lengths by their feed ids in traversal order. It
/// depends only on the registry, so every node tries the same routes in the
/// same order.
pub fn candidates(
    registry: &FeedRegistry,
    pair: &FeedDefinition,
) -> Result<Vec<Vec<ComputationPath>>, CrossPairError> {
    if pair.base == pair.quote {
        return Err(CrossPairError::SameAsset(pair.id));
    }
    let direct: Vec<&FeedDefinition> = registry
        .feeds()
        .filter(|feed| feed.kind == FeedKind::Direct)
        .collect();

    let mut routes = Vec::new();
    extend(
        &direct,
        pair.base,
        pair.quote,
        &mut vec![pair.base],
        &mut Vec::new(),
        &mut routes,
    );
    if routes.is_empty() {
        return Err(CrossPairError::NoRoute(pair.id));
    }
    routes.sort_by(|a, b| {
        a.len().cmp(&b.len()).then_with(|| {
            a.iter()
                .map(|leg| leg.feed)
                .cmp(b.iter().map(|leg| leg.feed))
        })
    });
    Ok(routes)
}

/// Walks on from `at`, never back to an asset the route already visited.
fn extend(
    direct: &[&FeedDefinition],
    at: Asset,
    quote: Asset,
    visited: &mut Vec<Asset>,
    route: &mut Vec<ComputationPath>,
    routes: &mut Vec<Vec<ComputationPath>>,
) {
    if at == quote {
        routes.push(route.clone());
        return;
    }
    for feed in direct {
        // Traversed from its quote to its base, a feed contributes its reciprocal.
        let (next, invert) = if feed.base == at {
            (feed.quote, false)
        } else if feed.quote == at {
            (feed.base, true)
        } else {
            continue;
        };
        if visited.contains(&next) {
            continue;
        }
        visited.push(next);
        route.push(ComputationPath {
            feed: feed.id,
            invert,
        });
        extend(direct, next, quote, visited, route, routes);
        route.pop();
        visited.pop();
    }
}

/// Prices a Cross pair at its own decimals from the values of its route's
/// legs, in i128. It is as new as its freshest leg and valid until its stalest
/// one, so the same legs always give the same value. `None` when the price
/// rounds to zero or does not fit in a `u64`.
pub fn compute(
    pair: &FeedDefinition,
    legs: &[(ComputationPath, PriceFeedData)],
) -> Option<PriceFeedData> {
    let (mut numerator, mut denominator) = (1i128, 1i128);
    let mut exponent = i64::from(pair.decimals);
    for (leg, value) in legs {
        if leg.invert {
            denominator = denominator.checked_mul(value.price.into())?;
            exponent += i64::from(value.decimals);
        } else {
            numerator = numerator.checked_mul(value.price.into())?;
            exponent -= i64::from(value.decimals);
        }
    }

    // N · 10^(decimals + dD − dN) / D
    let scale = 10i128.checked_pow(u32::try_from(exponent.unsigned_abs()).ok()?)?;
    let (numerator, denominator) = if exponent >= 0 {
        (numerator.checked_mul(scale)?, denominator)
    } else {
        (numerator, denominator.checked_mul(scale)?)
    };
    let price = u64::try_from(round_half_even(numerator, denominator)?)
        .ok()
        .filter(|price| *price != 0)?;

    Some(PriceFeedData {
        feed_id: pair.id,
        price,
        decimals: pair.decimals,
        received_at: legs.iter().map(|(_, value)| value.received_at).max()?,
        valid_until: legs.iter().map(|(_, value)| value.valid_until).min()?,
    })
}

/// `numerator / denominator` to the nearest whole number, an exact half to the
/// even one. Both are non-negative.
fn round_half_even(numerator: i128, denominator: i128) -> Option<i128> {
    let quotient = numerator.checked_div(denominator)?;
    let remainder = numerator % denominator;
    Some(match remainder.cmp(&(denominator - remainder)) {
        Ordering::Less => quotient,
        Ordering::Greater => quotient + 1,
        Ordering::Equal => quotient + quotient % 2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn leg(feed: FeedId, invert: bool) -> ComputationPath {
        ComputationPath { feed, invert }
    }

    fn value(feed: FeedId, price: u64, valid_until: u64) -> PriceFeedData {
        PriceFeedData {
            feed_id: feed,
            price,
            decimals: 8,
            received_at: NOW - 10,
            valid_until,
        }
    }

    fn pair() -> FeedDefinition {
        FeedDefinition::new(9, Asset::Lbtc, Asset::Usdt, FeedKind::Cross)
    }

    #[test]
    fn routes_every_registered_cross_pair_through_usd() {
        let registry = FeedRegistry::default();
        let routes = |feed| candidates(&registry, registry.get(feed).unwrap()).unwrap();

        assert_eq!(routes(4), [vec![leg(0, false), leg(1, true)]]);
        assert_eq!(routes(5), [vec![leg(2, false), leg(1, true)]]);
        assert_eq!(routes(6), [vec![leg(3, false), leg(1, true)]]);
    }

    #[test]
    fn orders_routes_by_length_then_by_their_feed_ids() {
        let registry = FeedRegistry::new([
            FeedDefinition::new(0, Asset::Eurx, Asset::Usd, FeedKind::Direct),
            FeedDefinition::new(1, Asset::Usdt, Asset::Usd, FeedKind::Direct),
            FeedDefinition::new(2, Asset::Eurx, Asset::Usdt, FeedKind::Direct),
            FeedDefinition::new(3, Asset::Eurx, Asset::Lbtc, FeedKind::Direct),
            FeedDefinition::new(5, Asset::Lbtc, Asset::Usd, FeedKind::Direct),
            FeedDefinition::new(6, Asset::Usdt, Asset::Lbtc, FeedKind::Direct),
            pair(),
        ]);

        let routes = candidates(&registry, registry.get(9).unwrap()).unwrap();

        assert_eq!(
            routes,
            [
                vec![leg(6, true)],
                vec![leg(3, true), leg(2, false)],
                vec![leg(5, false), leg(1, true)],
                vec![leg(3, true), leg(0, false), leg(1, true)],
                vec![leg(5, false), leg(0, true), leg(2, false)],
            ]
        );
    }

    #[test]
    fn rejects_a_pair_of_one_asset_or_without_a_route() {
        let registry = FeedRegistry::new([
            FeedDefinition::new(0, Asset::Lbtc, Asset::Usd, FeedKind::Direct),
            FeedDefinition::new(1, Asset::Usd, Asset::Usd, FeedKind::Cross),
            FeedDefinition::new(2, Asset::DePix, Asset::Lbtc, FeedKind::Cross),
        ]);
        let routes = |feed| candidates(&registry, registry.get(feed).unwrap());

        assert_eq!(routes(1), Err(CrossPairError::SameAsset(1)));
        assert_eq!(routes(2), Err(CrossPairError::NoRoute(2)));
    }

    #[test]
    fn prices_the_pair_at_its_own_decimals() {
        let legs = [
            (leg(0, false), value(0, 6_000_000_000_000, NOW + 50)),
            (
                leg(1, true),
                PriceFeedData {
                    received_at: NOW - 5,
                    ..value(1, 80_000_000, NOW + 30)
                },
            ),
        ];

        let price = compute(&pair(), &legs).unwrap();

        // As new as its freshest leg, valid while its stalest is.
        assert_eq!(
            price,
            PriceFeedData {
                feed_id: 9,
                price: 7_500_000_000_000,
                decimals: 8,
                received_at: NOW - 5,
                valid_until: NOW + 30,
            }
        );
    }

    #[test]
    fn rounds_the_last_decimal_to_the_nearest() {
        let legs = [
            (leg(0, false), value(0, 200_000_000, NOW + 60)),
            (leg(1, true), value(1, 300_000_000, NOW + 60)),
        ];

        let price = compute(&pair(), &legs).unwrap();

        assert_eq!(price.price, 66_666_667);
    }

    #[test]
    fn multiplies_the_legs_it_does_not_invert() {
        let legs = [
            (leg(0, false), value(0, 300_000_000, NOW + 60)),
            (leg(1, false), value(1, 200_000_000, NOW + 60)),
        ];

        let price = compute(&pair(), &legs).unwrap();

        assert_eq!(price.price, 600_000_000);
    }

    #[test]
    fn prices_nothing_that_rounds_to_zero_or_does_not_fit() {
        let whole = FeedDefinition {
            decimals: 0,
            ..pair()
        };
        let at_whole = |price| PriceFeedData {
            decimals: 0,
            ..value(0, price, NOW + 60)
        };
        let below_half = [(leg(0, false), at_whole(1)), (leg(1, true), at_whole(3))];
        let too_large = [
            (leg(0, false), at_whole(u64::MAX)),
            (leg(1, false), at_whole(2)),
        ];
        let overflowing = [
            (leg(0, false), at_whole(u64::MAX)),
            (leg(1, false), at_whole(u64::MAX)),
        ];

        assert_eq!(compute(&whole, &below_half), None);
        assert_eq!(compute(&whole, &too_large), None);
        assert_eq!(compute(&whole, &overflowing), None);
    }

    #[test]
    fn resolves_an_exact_half_to_the_even_neighbour() {
        assert_eq!(round_half_even(5, 2), Some(2));
        assert_eq!(round_half_even(7, 2), Some(4));
        assert_eq!(round_half_even(5, 4), Some(1));
        assert_eq!(round_half_even(7, 4), Some(2));
        assert_eq!(round_half_even(7, 0), None);
    }
}
