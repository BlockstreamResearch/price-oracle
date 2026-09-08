import { useEffect, useState } from 'react'
import { Eye, GitMerge, RefreshCw, Scissors, X } from 'lucide-react'
import { ApiError, authenticatedGet, signedPost } from '../api'
import { useAuth } from '../auth-context'
import { CopyableHex } from '../components/CopyableHex'
import { formatNumber } from '../format'
import type { OperatorSession, StormEyesState, StormEyeState, VotingProposal } from '../types'

type Filter = 'all' | StormEyeState

function fetchStormEyes(session: OperatorSession) {
  return authenticatedGet<StormEyesState>(session, '/operators/storm-eyes')
}

export function StormEyesPage() {
  const { session, logout } = useAuth()
  const [inventory, setInventory] = useState<StormEyesState | null>(null)
  const [filter, setFilter] = useState<Filter>('all')
  const [loading, setLoading] = useState(true)
  const [actionBusy, setActionBusy] = useState(false)
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [error, setError] = useState('')

  function updateInventory(nextInventory: StormEyesState) {
    setInventory(nextInventory)
    const available = new Set(nextInventory.utxos
      .filter((utxo) => utxo.state === 'available')
      .map((utxo) => `${utxo.txid}:${utxo.output_index}`))
    setSelectedKeys((current) => current.filter((key) => available.has(key)))
  }

  async function load() {
    if (!session) return
    setLoading(true)
    setError('')
    try { updateInventory(await fetchStormEyes(session)) }
    catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) logout()
      else setError(cause instanceof Error ? cause.message : 'Could not load Storm Eye UTXOs.')
    } finally { setLoading(false) }
  }

  useEffect(() => {
    if (!session) return
    let active = true
    fetchStormEyes(session)
      .then((nextInventory) => { if (active) updateInventory(nextInventory) })
      .catch((cause: unknown) => {
        if (!active) return
        if (cause instanceof ApiError && cause.status === 401) logout()
        else setError(cause instanceof Error ? cause.message : 'Could not load Storm Eye UTXOs.')
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [session, logout])

  const utxos = inventory?.utxos ?? []
  const count = (state: StormEyeState) => utxos.filter((utxo) => utxo.state === state).length
  const visible = filter === 'all' ? utxos : utxos.filter((utxo) => utxo.state === filter)
  const totalAmount = utxos.reduce((total, utxo) => total + utxo.amount, 0)
  const selected = utxos.filter((utxo) => selectedKeys.includes(`${utxo.txid}:${utxo.output_index}`))
  const selectedAmount = selected.reduce((total, utxo) => total + utxo.amount, 0)

  function toggleSelection(key: string) {
    setSelectedKeys((current) => current.includes(key)
      ? current.filter((selectedKey) => selectedKey !== key)
      : current.length < 3 ? [...current, key] : current)
  }

  async function createVoting(proposal: VotingProposal) {
    if (!session) return
    setActionBusy(true)
    setError('')
    try {
      await signedPost<{ message_hash: string }>(session, '/operators/voting', proposal)
      setSelectedKeys([])
      await load()
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) logout()
      else setError(cause instanceof Error ? cause.message : 'Could not create voting.')
    } finally { setActionBusy(false) }
  }

  function splitSelected(numberOfSplits: number) {
    const [utxo] = selected
    if (!utxo) return
    void createVoting({
      kind: 'split_storm_eye',
      utxo_to_split: { txid: utxo.txid, output_index: utxo.output_index },
      number_of_splits: numberOfSplits,
    })
  }

  function mergeSelected() {
    if (selected.length < 2) return
    void createVoting({
      kind: 'merge_storm_eyes',
      utxos_to_merge: selected.map(({ txid, output_index }) => ({ txid, output_index })),
    })
  }

  return <div className="page storm-eyes-page">
    <header className="page-header"><div><span className="eyebrow">Network authentication</span><h1>Storm Eyes</h1>
      <p>Inspect every live Storm Eye UTXO and its current governance reservation state.</p></div>
      <button className="secondary-button icon-only-mobile" type="button" onClick={() => void load()} disabled={loading}>
        <RefreshCw size={16} className={loading ? 'spin' : ''} /><span>Refresh</span>
      </button>
    </header>
    {error && <div className="page-error" role="alert">{error}</div>}

    <section className="storm-eye-summary" aria-label="Storm Eye inventory summary">
      <div><span>Total UTXOs</span><strong>{inventory ? utxos.length : '—'}</strong><small>{formatNumber(totalAmount)} total units</small></div>
      <div><span>Available</span><strong>{inventory ? count('available') : '—'}</strong><small>ready for network operations</small></div>
      <div><span>Proposed</span><strong>{inventory ? count('proposed') : '—'}</strong><small>referenced by an open vote</small></div>
      <div><span>Executing</span><strong>{inventory ? count('executing') : '—'}</strong><small>locked by active execution</small></div>
    </section>

    <section className="storm-eye-inventory">
      <div className="voting-toolbar">
        <div className="segmented" aria-label="Filter Storm Eye UTXOs">
          {(['all', 'available', 'proposed', 'executing'] as Filter[]).map((value) =>
            <button type="button" className={filter === value ? 'active' : ''} key={value} onClick={() => setFilter(value)}>
              {value}<span>{value === 'all' ? utxos.length : count(value)}</span>
            </button>)}
        </div>
        <span className="result-count">Block {inventory ? formatNumber(inventory.block_height) : '—'} · {visible.length} live outputs</span>
      </div>

      {selected.length > 0 && <div className="storm-eye-selection" aria-live="polite">
        <div><strong>{selected.length} selected</strong><span>{formatNumber(selectedAmount)} STORM</span></div>
        <div className="storm-eye-selection-actions">
          {selected.length === 1 && <>
            <button className="secondary-button" type="button" disabled={actionBusy} onClick={() => splitSelected(2)}><Scissors size={16} /> Split into 2</button>
            <button className="primary-button" type="button" disabled={actionBusy} onClick={() => splitSelected(3)}><Scissors size={16} /> Split into 3</button>
          </>}
          {selected.length > 1 && <button className="primary-button" type="button" disabled={actionBusy} onClick={mergeSelected}>
            <GitMerge size={16} /> {actionBusy ? 'Creating voting…' : `Merge ${selected.length} Storm Eyes`}
          </button>}
          <button className="icon-button" type="button" title="Clear selection" disabled={actionBusy} onClick={() => setSelectedKeys([])}><X size={17} /></button>
        </div>
      </div>}

      <div className="table-wrap storm-eye-table-wrap">
        <table className="storm-eye-table">
          <thead><tr><th>Select</th><th>Outpoint</th><th>Amount</th><th>Confirmations</th><th>State</th><th>Voting requests</th></tr></thead>
          <tbody>
            {visible.map((utxo) => {
              const key = `${utxo.txid}:${utxo.output_index}`
              const checked = selectedKeys.includes(key)
              const disabled = utxo.state !== 'available' || (!checked && selected.length >= 3)
              return <tr className={checked ? 'selected' : ''} key={key}>
              <td className="storm-eye-select-cell" data-label="Select"><input type="checkbox" checked={checked} disabled={disabled}
                aria-label={`Select Storm Eye ${utxo.txid} output ${utxo.output_index}`} onChange={() => toggleSelection(key)} /></td>
              <td data-label="Outpoint"><div className="storm-eye-outpoint"><span><Eye size={16} /></span><div><CopyableHex value={utxo.txid} visible={10} label="Storm Eye transaction ID" /><small>Output {utxo.output_index}</small></div></div></td>
              <td className="storm-eye-amount" data-label="Amount">{formatNumber(utxo.amount)} <small>STORM</small></td>
              <td className="muted-cell" data-label="Confirmations">{formatNumber(utxo.confirmations)}</td>
              <td data-label="State"><span className={`status-pill ${utxo.state}`}>{utxo.state}</span></td>
              <td data-label="Voting requests">{utxo.voting_request_hashes.length === 0 ? <span className="muted-cell">—</span> : <div className="storm-eye-votes">
                {utxo.voting_request_hashes.map((hash) => <CopyableHex key={hash} value={hash} visible={7} label="voting request hash" />)}
              </div>}</td>
            </tr>})}
            {!loading && visible.length === 0 && <tr><td className="empty-row" colSpan={6}>No Storm Eye UTXOs match this state.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  </div>
}