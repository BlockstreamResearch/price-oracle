use serde::{Deserialize, Serialize};

pub type FeedId = u32;

pub const FEED_DECIMALS: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Asset {
    Lbtc, // Liquid Bitcoin
    Usd,

    // Tether USD
    Usdt,

    // PEGx EUR
    Eurx,

    // Decentralized Pix
    DePix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedKind {
    // The source prices this feed directly
    Direct,

    // Derived from Direct feeds at runtime
    Cross,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedDefinition {
    pub id: FeedId,
    pub base: Asset,
    pub quote: Asset,
    pub kind: FeedKind,
    pub decimals: u32,
}

impl FeedDefinition {
    const fn new(id: FeedId, base: Asset, quote: Asset, kind: FeedKind) -> Self {
        Self {
            id,
            base,
            quote,
            kind,
            decimals: FEED_DECIMALS,
        }
    }
}

const SUPPORTED_FEEDS: [FeedDefinition; 7] = [
    FeedDefinition::new(0, Asset::Lbtc, Asset::Usd, FeedKind::Direct),
    FeedDefinition::new(1, Asset::Usdt, Asset::Usd, FeedKind::Direct),
    FeedDefinition::new(2, Asset::Eurx, Asset::Usd, FeedKind::Direct),
    FeedDefinition::new(3, Asset::DePix, Asset::Usd, FeedKind::Direct),
    FeedDefinition::new(4, Asset::Lbtc, Asset::Usdt, FeedKind::Cross),
    FeedDefinition::new(5, Asset::Eurx, Asset::Usdt, FeedKind::Cross),
    FeedDefinition::new(6, Asset::DePix, Asset::Usdt, FeedKind::Cross),
];

/// Ordered by feed id, so every node enumerates feeds alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedRegistry {
    feeds: Vec<FeedDefinition>,
}

impl FeedRegistry {
    pub fn new(feeds: impl IntoIterator<Item = FeedDefinition>) -> Self {
        let mut feeds: Vec<_> = feeds.into_iter().collect();
        feeds.sort_by_key(|feed| feed.id);
        Self { feeds }
    }

    pub fn get(&self, feed: FeedId) -> Option<&FeedDefinition> {
        self.feeds.iter().find(|definition| definition.id == feed)
    }

    pub fn feeds(&self) -> impl Iterator<Item = &FeedDefinition> {
        self.feeds.iter()
    }
}

impl Default for FeedRegistry {
    fn default() -> Self {
        Self::new(SUPPORTED_FEEDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> FeedRegistry {
        FeedRegistry::new([
            FeedDefinition::new(2, Asset::Eurx, Asset::Usdt, FeedKind::Cross),
            FeedDefinition::new(0, Asset::Lbtc, Asset::Usd, FeedKind::Direct),
            FeedDefinition::new(1, Asset::Usdt, Asset::Usd, FeedKind::Direct),
        ])
    }

    #[test]
    fn orders_feeds_by_id_however_they_are_registered() {
        let ids: Vec<_> = registry().feeds().map(|feed| feed.id).collect();

        assert_eq!(ids, [0, 1, 2]);
    }

    #[test]
    fn resolves_nothing_for_an_unregistered_feed() {
        let registry = registry();

        assert_eq!(registry.get(3), None);
    }

    #[test]
    fn supported_feeds_match_the_specification() {
        let feeds: Vec<_> = FeedRegistry::default()
            .feeds()
            .map(|feed| (feed.id, feed.base, feed.quote, feed.kind))
            .collect();

        assert_eq!(
            feeds,
            [
                (0, Asset::Lbtc, Asset::Usd, FeedKind::Direct),
                (1, Asset::Usdt, Asset::Usd, FeedKind::Direct),
                (2, Asset::Eurx, Asset::Usd, FeedKind::Direct),
                (3, Asset::DePix, Asset::Usd, FeedKind::Direct),
                (4, Asset::Lbtc, Asset::Usdt, FeedKind::Cross),
                (5, Asset::Eurx, Asset::Usdt, FeedKind::Cross),
                (6, Asset::DePix, Asset::Usdt, FeedKind::Cross),
            ]
        );
    }
}
