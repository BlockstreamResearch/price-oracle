import { useEffect, useState, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import { ArrowRight, CheckCircle2, Eye, Plus, RefreshCw, Vote, X } from 'lucide-react'
import { ApiError, authenticatedGet, signedPost } from '../api'
import { useAuth } from '../auth-context'
import { formatNumber, proposalName, proposalSummary, shortKey } from '../format'
import type { OperatorSession, Utxo, Voting, VotingProposal } from '../types'

type Filter = 'all' | 'pending' | 'approved'

function fetchVotings(session: OperatorSession) {
  return authenticatedGet<Voting[]>(session, '/operators/voting')
}

export function VotingsPage() {
  const { session, logout } = useAuth()
  const [votings, setVotings] = useState<Voting[]>([])
  const [filter, setFilter] = useState<Filter>('all')
  const [selected, setSelected] = useState<Voting | null>(null)
  const [creating, setCreating] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [actionBusy, setActionBusy] = useState(false)

  async function load() {
    if (!session) return
    setLoading(true); setError('')
    try { setVotings(await fetchVotings(session)) }
    catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) logout()
      else setError(cause instanceof Error ? cause.message : 'Could not load votings.')
    } finally { setLoading(false) }
  }

  useEffect(() => {
    if (!session) return
    let active = true
    fetchVotings(session)
      .then((nextVotings) => { if (active) setVotings(nextVotings) })
      .catch((cause: unknown) => {
        if (!active) return
        if (cause instanceof ApiError && cause.status === 401) logout()
        else setError(cause instanceof Error ? cause.message : 'Could not load votings.')
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [session, logout])

  async function create(proposal: VotingProposal) {
    if (!session) return
    setActionBusy(true)
    try {
      await signedPost<{ message_hash: string }>(session, '/operators/voting', proposal)
      setCreating(false); await load()
    } finally { setActionBusy(false) }
  }

  async function approve(voting: Voting) {
    if (!session) return
    setActionBusy(true); setError('')
    try {
      await signedPost<void>(session, `/operators/voting/${voting.message_hash}/approve`, {})
      setSelected(null); await load()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not approve voting.')
    } finally { setActionBusy(false) }
  }

  const visible = filter === 'all' ? votings : votings.filter((voting) => voting.status === filter)

  return (
    <div className="page">
      <header className="page-header"><div><span className="eyebrow">Network governance</span><h1>Votings</h1>
        <p>Create proposals, inspect approvals and sign network decisions.</p></div>
        <div className="header-actions"><button className="secondary-button icon-only-mobile" type="button" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={16} className={loading ? 'spin' : ''} /><span>Refresh</span></button>
          <button className="primary-button" type="button" onClick={() => setCreating(true)}><Plus size={17} /> New voting</button></div>
      </header>
      {error && <div className="page-error" role="alert">{error}</div>}
      <section className="voting-toolbar">
        <div className="segmented" aria-label="Filter votings">
          {(['all', 'pending', 'approved'] as Filter[]).map((value) =>
            <button type="button" className={filter === value ? 'active' : ''} key={value} onClick={() => setFilter(value)}>
              {value}<span>{value === 'all' ? votings.length : votings.filter((item) => item.status === value).length}</span>
            </button>)}
        </div>
        <span className="result-count">{visible.length} results</span>
      </section>
      <section className="voting-list">
        <div className="voting-list-head"><span>Proposal</span><span>Created</span><span>Approvals</span><span>Status</span><span /></div>
        {visible.map((voting) => <article className="voting-row" key={voting.message_hash}>
          <div className="proposal-cell"><span className="proposal-icon"><Vote size={18} /></span><div>
            <strong>{proposalName(voting.proposal)}</strong><small>{proposalSummary(voting.proposal)} · {shortKey(voting.message_hash, 7)}</small></div></div>
          <span className="block-cell">Block {formatNumber(voting.block_height)}</span>
          <span className="approval-count">{voting.approvals.length}</span>
          <span className={`status-pill ${voting.status}`}>{voting.status === 'approved' && <CheckCircle2 size={13} />}{voting.status}</span>
          <button className="icon-button" type="button" title="View voting" onClick={() => setSelected(voting)}><Eye size={17} /></button>
        </article>)}
        {!loading && visible.length === 0 && <div className="empty-state"><Vote size={25} /><strong>No votings found</strong><span>Create a proposal or change the current filter.</span></div>}
      </section>

      {creating && <Modal title="Create voting" onClose={() => !actionBusy && setCreating(false)}>
        <VotingForm busy={actionBusy} onCancel={() => setCreating(false)} onSubmit={create} />
      </Modal>}
      {selected && <Modal title="Voting details" onClose={() => setSelected(null)}>
        <VotingDetail voting={selected} busy={actionBusy} onApprove={() => void approve(selected)} />
      </Modal>}
    </div>
  )
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return createPortal(<div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-label={title}>
    <header><div><span className="eyebrow">Network governance</span><h2>{title}</h2></div>
      <button className="icon-button" type="button" title="Close" onClick={onClose}><X size={18} /></button></header>{children}</section></div>, document.body)
}

function VotingDetail({ voting, busy, onApprove }: { voting: Voting; busy: boolean; onApprove: () => void }) {
  return <div className="voting-detail">
    <dl className="detail-grid"><div><dt>Status</dt><dd><span className={`status-pill ${voting.status}`}>{voting.status}</span></dd></div>
      <div><dt>Created at</dt><dd>Block {formatNumber(voting.block_height)}</dd></div><div className="full"><dt>Message hash</dt><dd><code>{voting.message_hash}</code></dd></div>
      <div className="full"><dt>Proposal</dt><dd><strong>{proposalName(voting.proposal)}</strong><span>{proposalSummary(voting.proposal)}</span></dd></div></dl>
    <div className="approval-section"><h3>Approvals <span>{voting.approvals.length}</span></h3>
      {voting.approvals.map((approval) => <div className="approval-row" key={`${approval.public_key}-${approval.block_height}`}>
        <code>{shortKey(approval.public_key, 10)}</code><span>Block {formatNumber(approval.block_height)}</span></div>)}
      {voting.approvals.length === 0 && <p>No approvals recorded.</p>}</div>
    {voting.status === 'pending' && <footer className="modal-actions"><button className="primary-button" type="button" disabled={busy} onClick={onApprove}>
      <CheckCircle2 size={17} /> {busy ? 'Signing…' : 'Approve voting'}</button></footer>}
  </div>
}

function VotingForm({ busy, onCancel, onSubmit }: { busy: boolean; onCancel: () => void; onSubmit: (proposal: VotingProposal) => Promise<void> }) {
  const [kind, setKind] = useState<VotingProposal['kind']>('update_network_members')
  const [accept, setAccept] = useState(''); const [remove, setRemove] = useState('')
  const [utxos, setUtxos] = useState<Utxo[]>([{ txid: '', output_index: 0 }, { txid: '', output_index: 1 }])
  const [splitTxid, setSplitTxid] = useState(''); const [splitIndex, setSplitIndex] = useState(0)
  const [splitCount, setSplitCount] = useState(2); const [error, setError] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault(); setError('')
    const lines = (value: string) => value.split(/\s+/).map((line) => line.trim()).filter(Boolean)
    let proposal: VotingProposal
    if (kind === 'update_network_members') proposal = { kind, to_accept: lines(accept), to_remove: lines(remove) }
    else if (kind === 'merge_storm_eyes') proposal = { kind, utxos_to_merge: utxos }
    else proposal = { kind, utxo_to_split: { txid: splitTxid.trim(), output_index: splitIndex }, number_of_splits: splitCount }
    try { await onSubmit(proposal) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not create voting.') }
  }

  function updateUtxo(index: number, field: keyof Utxo, value: string) {
    setUtxos((current) => current.map((utxo, row) => row === index
      ? { ...utxo, [field]: field === 'output_index' ? Number(value) : value } : utxo))
  }

  return <form className="voting-form" onSubmit={submit}>
    <fieldset><legend>Proposal type</legend><div className="proposal-kinds">
      <label className={kind === 'update_network_members' ? 'selected' : ''}><input type="radio" name="kind" checked={kind === 'update_network_members'} onChange={() => setKind('update_network_members')} /><span>Members</span><small>Add or remove signers</small></label>
      <label className={kind === 'merge_storm_eyes' ? 'selected' : ''}><input type="radio" name="kind" checked={kind === 'merge_storm_eyes'} onChange={() => setKind('merge_storm_eyes')} /><span>Merge</span><small>Combine Storm Eyes</small></label>
      <label className={kind === 'split_storm_eye' ? 'selected' : ''}><input type="radio" name="kind" checked={kind === 'split_storm_eye'} onChange={() => setKind('split_storm_eye')} /><span>Split</span><small>Divide a Storm Eye</small></label>
    </div></fieldset>
    {kind === 'update_network_members' && <div className="form-grid two"><label>Public keys to accept<textarea rows={4} value={accept} onChange={(event) => setAccept(event.target.value)} placeholder="One x-only public key per line" /></label>
      <label>Public keys to remove<textarea rows={4} value={remove} onChange={(event) => setRemove(event.target.value)} placeholder="One x-only public key per line" /></label></div>}
    {kind === 'merge_storm_eyes' && <fieldset><legend>UTXOs to merge</legend><div className="utxo-list">{utxos.map((utxo, index) => <div className="utxo-row" key={index}>
      <label>Transaction ID<input value={utxo.txid} onChange={(event) => updateUtxo(index, 'txid', event.target.value)} required /></label>
      <label>Output<input type="number" min="0" value={utxo.output_index} onChange={(event) => updateUtxo(index, 'output_index', event.target.value)} required /></label>
      {utxos.length > 2 && <button className="icon-button" type="button" title="Remove UTXO" onClick={() => setUtxos((rows) => rows.filter((_, row) => row !== index))}><X size={16} /></button>}</div>)}</div>
      <button className="text-button" type="button" onClick={() => setUtxos((rows) => [...rows, { txid: '', output_index: 0 }])}><Plus size={15} /> Add UTXO</button></fieldset>}
    {kind === 'split_storm_eye' && <div className="form-grid split"><label>Transaction ID<input value={splitTxid} onChange={(event) => setSplitTxid(event.target.value)} required /></label>
      <label>Output index<input type="number" min="0" value={splitIndex} onChange={(event) => setSplitIndex(Number(event.target.value))} required /></label>
      <label>Number of splits<input type="number" min="2" value={splitCount} onChange={(event) => setSplitCount(Number(event.target.value))} required /></label></div>}
    {error && <div className="form-error" role="alert">{error}</div>}
    <footer className="modal-actions"><button className="secondary-button" type="button" onClick={onCancel}>Cancel</button>
      <button className="primary-button" disabled={busy}>{busy ? 'Signing proposal…' : 'Create voting'}<ArrowRight size={17} /></button></footer>
  </form>
}