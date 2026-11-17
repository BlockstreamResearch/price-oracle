//! Price observations, sources and attestations.

use crate::high_storm::*;

impl HighStorm {
    /// Returns how many feeds were attested.
    pub async fn attest_prices(&self) -> Result<usize, PriceError> {
        self.state.prices().attest(&self.storm.handle()).await
    }
}

impl HighStormHandle {
    /// Only a Direct feed has sources. Named with a Cross pair, this and the
    /// two below do nothing, since it is priced from the feeds it joins.
    pub async fn record_price_observation(
        &self,
        feed: price_feed::FeedId,
        source: usize,
        observation: price_feed::SourceObservation,
    ) {
        self.state
            .prices()
            .record_observation(feed, source, observation)
            .await
    }

    pub async fn record_price_failure(&self, feed: price_feed::FeedId, source: usize) {
        self.state.prices().record_failure(feed, source).await
    }

    pub async fn poll_price_source<S: price_feed::PriceSource>(
        &self,
        feed: price_feed::FeedId,
        index: usize,
        name: &'static str,
        source: &S,
    ) -> PollOutcome {
        self.state.prices().poll(feed, index, name, source).await
    }

    /// Lists the source under the feed it prices, frozen again if this node's
    /// operator froze it before a restart.
    pub async fn register_price_source(
        &self,
        feed: price_feed::FeedId,
        index: usize,
        name: &'static str,
    ) -> Result<(), PriceSourceError> {
        self.state.prices().register_source(feed, index, name).await
    }

    /// Local to this node: nothing is broadcast, and only the price this node
    /// attests and signs changes.
    pub async fn set_price_source_frozen(
        &self,
        feed: price_feed::FeedId,
        source: &str,
        frozen: bool,
    ) -> Result<(), PriceSourceError> {
        self.state
            .prices()
            .set_source_frozen(feed, source, frozen)
            .await
    }

    /// Every Direct feed with the sources this node prices it from.
    pub async fn price_sources(&self) -> Result<Vec<FeedSources>, PriceSourceError> {
        self.state.prices().sources().await
    }

    pub async fn price_attestations(
        &self,
        feed: price_feed::FeedId,
    ) -> Result<Vec<PriceAttestation>, PriceError> {
        self.state.prices().attestations_for(feed).await
    }

    pub(crate) async fn price_health(
        &self,
        sources: &[(price_feed::FeedId, usize)],
        feeds: &[price_feed::FeedId],
    ) -> PriceHealth {
        self.state.prices().health(sources, feeds).await
    }

    /// Every feed this node prices, in id order.
    pub fn price_feeds(&self) -> Vec<price_feed::FeedDefinition> {
        self.state.prices().registry().feeds().copied().collect()
    }

    pub fn price_feed(&self, feed: price_feed::FeedId) -> Option<price_feed::FeedDefinition> {
        self.state.prices().registry().get(feed).copied()
    }

    pub async fn exchange_rate(&self, feed: price_feed::FeedId) -> Result<FeedRate, PriceError> {
        let peers = self.peers().await;
        let members = voting::member_keys(&peers)
            .map_err(|error| PriceError::InvalidPeerKey(error.to_string()))?;

        self.state.prices().rate_for(feed, &members).await
    }

    /// Whether a round prepared now would hold a rate to issue this feed at.
    pub async fn has_round_rate(&self, feed: price_feed::FeedId) -> bool {
        user_requests::has_round_rate(self.state.prices(), feed).await
    }
}
