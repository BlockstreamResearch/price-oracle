use storm::{Peer, PeerStatus};

pub(crate) fn leader_for_height(peers: &[Peer], block_height: u64) -> Option<[u8; 33]> {
    let mut members = peers
        .iter()
        .map(|peer| peer.compressed_public_key)
        .collect::<Vec<_>>();
    members.sort_unstable();
    members.dedup();
    let index = usize::try_from(block_height % u64::try_from(members.len()).ok()?).ok()?;
    members.get(index).copied()
}

pub(crate) fn local_public_key(peers: &[Peer]) -> Option<[u8; 33]> {
    peers
        .iter()
        .find(|peer| peer.status == PeerStatus::Controlled)
        .map(|peer| peer.compressed_public_key)
}

pub(crate) fn is_local_leader(peers: &[Peer], block_height: u64) -> bool {
    local_public_key(peers) == leader_for_height(peers, block_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peers(keys: &[[u8; 33]]) -> Vec<Peer> {
        keys.iter().copied().map(Peer::new).collect()
    }

    #[test]
    fn rotates_leader_once_per_block_in_sorted_member_order() {
        let peers = peers(&[[3; 33], [1; 33], [2; 33]]);

        assert_eq!(leader_for_height(&peers, 0), Some([1; 33]));
        assert_eq!(leader_for_height(&peers, 1), Some([2; 33]));
        assert_eq!(leader_for_height(&peers, 2), Some([3; 33]));
        assert_eq!(leader_for_height(&peers, 3), Some([1; 33]));
    }

    #[test]
    fn peer_order_and_status_do_not_change_the_leader() {
        let mut first = peers(&[[1; 33], [2; 33], [3; 33]]);
        first[1].status = PeerStatus::Inactive;
        let mut second = peers(&[[3; 33], [2; 33], [1; 33]]);
        second[1].status = PeerStatus::Banned;

        assert_eq!(leader_for_height(&first, 1), leader_for_height(&second, 1));
    }

    #[test]
    fn only_the_selected_network_leader_can_run_the_round() {
        let mut peers = peers(&[[1; 33], [2; 33], [3; 33]]);
        peers[1].status = PeerStatus::Controlled;

        assert!(is_local_leader(&peers, 1));
        assert!(!is_local_leader(&peers, 0));
        assert!(!is_local_leader(&peers, 2));
    }
}
