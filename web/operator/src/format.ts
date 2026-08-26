import type { VotingProposal } from "./types";

export function shortKey(value: string, visible = 8) {
  return `${value.slice(0, visible)}…${value.slice(-visible)}`;
}

export function formatNumber(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatTimestamp(value: number | null) {
  if (value === null) return "Never";
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value * 1000));
}

export function proposalName(proposal: VotingProposal) {
  switch (proposal.kind) {
    case "update_network_members":
      return "Update network members";
    case "merge_storm_eyes":
      return "Merge Storm Eyes";
    case "split_storm_eye":
      return "Split Storm Eye";
  }
}

export function proposalSummary(proposal: VotingProposal) {
  switch (proposal.kind) {
    case "update_network_members":
      return `${proposal.to_accept.length} added, ${proposal.to_remove.length} removed`;
    case "merge_storm_eyes":
      return `${proposal.utxos_to_merge.length} UTXOs`;
    case "split_storm_eye":
      return `${proposal.number_of_splits} outputs`;
  }
}
