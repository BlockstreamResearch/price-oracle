export type NetworkState = {
  block_height: number;
  local_public_key: string;
  coordinator_public_key: string;
  is_coordinator: boolean;
  total_peers: number;
  online_peers: number;
  inactive_peers: number;
  banned_peers: number;
  pending_votings: number;
  approved_votings: number;
};

export type NetworkPeer = {
  public_key: string;
  socket_address: string | null;
  last_seen: number | null;
  status: "controlled" | "active" | "inactive" | "banned";
  is_local: boolean;
  is_coordinator: boolean;
};

export type Utxo = {
  txid: string;
  output_index: number;
};

export type VotingProposal =
  | {
      kind: "update_network_members";
      to_accept: string[];
      to_remove: string[];
    }
  | {
      kind: "merge_storm_eyes";
      utxos_to_merge: Utxo[];
    }
  | {
      kind: "split_storm_eye";
      utxo_to_split: Utxo;
      number_of_splits: number;
    };

export type VotingApproval = {
  public_key: string;
  block_height: number;
};

export type Voting = {
  message_hash: string;
  proposal: VotingProposal;
  block_height: number;
  status: "pending" | "approved";
  approvals: VotingApproval[];
};

export type OperatorIdentity = {
  publicKey: string;
  address: string;
  sign: (message: string) => Promise<string>;
  destroy: () => void;
};

export type OperatorSession = {
  token: string;
  expiresAt: number;
  identity: OperatorIdentity;
};
