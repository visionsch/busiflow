// @ts-nocheck
import { useEffect, useMemo, useState } from 'react';
import { api } from './shims/client';
import { Activity, ArrowDownToLine, Ban, Bell, Building2, Check, ChevronRight, CircleAlert, Copy, ExternalLink, FileCheck2, Link2, LogOut, RefreshCw, Search, ShieldCheck, Store, Users, Wallet, X } from 'lucide-react';

type Row = Record<string, any>;
type Props = { user: Row; csrf: string; onLogout: () => void };

const money = (value: number) => new Intl.NumberFormat('en-GH', { style: 'currency', currency: 'GHS' }).format(Number(value) || 0);
const date = (value: string) => value ? new Date(value).toLocaleString() : '—';

export default function SuperAdminDashboard({ user, onLogout }: Props) {
  const [tab, setTab] = useState('overview');
  const [data, setData] = useState<Row>({ stats: {}, workspaces: [], applications: [], registrationLinks: [], notifications: [] });
  const [pushBusy, setPushBusy] = useState(false);
  const [query, setQuery] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [expiry, setExpiry] = useState('7');
  const [selected, setSelected] = useState<Row | null>(null);
  const [claimUrl, setClaimUrl] = useState('');
  const [linkUrls, setLinkUrls] = useState<Record<string, string>>({});
  const [rejectReason, setRejectReason] = useState('');
  const [rejecting, setRejecting] = useState<Row | null>(null);

  const post = async (path: string, body: Row = {}) => {
    // Fetch the token bound to the current HttpOnly session immediately before each privileged write.
    // This avoids using a stale React prop after a session refresh or re-authentication.
    const sessionResponse = await api.get('/api/auth/session');
    const session = sessionResponse.data || {};
    const freshCsrf = String(session.csrfToken || '');
    if (!session.authenticated || session.user?.role !== 'Super Admin' || !freshCsrf) {
      throw new Error('Your Super Admin session has expired or changed. Refresh the page and sign in again.');
    }
    return api.post(path, { ...body, _csrf: freshCsrf });
  };
  async function load() {
    setBusy(true);
    try {
      const response = await api.get('/api/super-admin/dashboard');
      setData(response.data);
      setNotice('');
    } catch (error: any) {
      setNotice(error?.response?.data?.error || error?.message || 'Platform data could not be loaded.');
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => { void load(); }, []);

  const workspaces = useMemo(() => (data.workspaces || []).filter((x: Row) => JSON.stringify(x).toLowerCase().includes(query.toLowerCase())), [data.workspaces, query]);
  const applications = useMemo(() => (data.applications || []).filter((x: Row) => JSON.stringify(x).toLowerCase().includes(query.toLowerCase())), [data.applications, query]);
  const links = data.registrationLinks || [];

  async function createLink() {
    setBusy(true);
    try {
      const response = await post('/api/super-admin/registration-links', { expiresInDays: Number(expiry) });
      await navigator.clipboard?.writeText(response.data.link.url);
      setNotice('Registration link created. It has been copied if clipboard access is available.');
      await load();
      setClaimUrl(response.data.link.url);
    } catch (error: any) {
      setNotice(error?.response?.data?.error || error?.message || 'Registration link could not be created.');
    } finally { setBusy(false); }
  }
  async function decide(application: Row, decision: string) {
    if (decision === 'reject' && rejectReason.trim().length < 5) { setNotice('Enter a reason of at least five characters.'); return; }
    setBusy(true);
    try {
      const response = await post('/api/super-admin/applications/decision', { applicationId: application.id, decision, reason: rejectReason });
      if (response.data.claimUrl) {
        setClaimUrl(response.data.claimUrl);
        await navigator.clipboard?.writeText(response.data.claimUrl);
        setNotice('Application approved. The one-time Managing Director claim link has been copied if clipboard access is available.');
      } else setNotice('Application rejected and the decision was recorded.');
      setRejecting(null); setRejectReason('');
      await load();
    } catch (error: any) {
      setNotice(error?.response?.data?.error || error?.message || 'Application decision could not be saved.');
    } finally { setBusy(false); }
  }
  async function changeWorkspaceStatus(workspace: Row) {
    const status = workspace.status === 'suspended' ? 'active' : 'suspended';
    if (!window.confirm(status === 'suspended' ? 'Suspend this workspace? Its users will no longer be able to sign in.' : 'Reactivate this workspace?')) return;
    setBusy(true);
    try {
      await post('/api/super-admin/workspaces/status', { workspaceId: workspace.id, status });
      setNotice(workspace.name + ' is now ' + status + '.');
      await load();
      if (selected?.id === workspace.id) setSelected({ ...selected, status });
    } catch (error: any) { setNotice(error?.response?.data?.error || error?.message || 'Workspace status could not be changed.'); }
    finally { setBusy(false); }
  }
  async function openApplicationDocument(application: Row, document: Row) {
    try {
      const response = await api.get('/api/super-admin/applications/document?applicationId=' + encodeURIComponent(application.id) + '&kind=' + encodeURIComponent(document.kind));
      window.open(response.data.url, '_blank', 'noopener,noreferrer');
    } catch (error: any) { setNotice(error?.response?.data?.error || 'The private application document could not be opened.'); }
  }
  async function markNotificationRead(item: Row) {
    try {
      await post('/api/super-admin/notifications/read', { id: item.id });
      setData((old: Row) => ({ ...old, notifications: (old.notifications || []).map((entry: Row) => entry.id === item.id ? { ...entry, readAt: new Date().toISOString() } : entry), stats: { ...old.stats, unreadNotifications: Math.max(0, Number(old.stats?.unreadNotifications || 0) - (item.readAt ? 0 : 1)) } }));
    } catch (error: any) { setNotice(error?.response?.data?.error || 'Alert could not be marked as read.'); }
  }
  async function enablePushAlerts() {
    setPushBusy(true);
    try {
      if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) throw new Error('This browser does not support Web Push.');
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') throw new Error('Notification permission was not granted. In-app alerts remain available.');
      const registration = await navigator.serviceWorker.register('/push-sw.js');
      const response = await api.get('/api/push/vapid-public-key');
      const value = String(response.data.publicKey || '');
      const padding = '='.repeat((4 - value.length % 4) % 4);
      const raw = atob((value + padding).replace(/-/g, '+').replace(/_/g, '/'));
      const applicationServerKey = Uint8Array.from(raw, character => character.charCodeAt(0));
      let subscription = await registration.pushManager.getSubscription();
      if (!subscription) subscription = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey });
      await post('/api/push/subscribe', { subscription: subscription.toJSON() });
      setNotice('Super Admin push alerts are enabled on this device.');
    } catch (error: any) { setNotice(error?.response?.data?.error || error?.message || 'Push alerts could not be enabled.'); }
    finally { setPushBusy(false); }
  }
  async function inspectWorkspace(workspace: Row) {
    setBusy(true);
    try {
      const response = await api.get('/api/super-admin/workspaces/detail?workspaceId=' + encodeURIComponent(workspace.id));
      setSelected(response.data);
    } catch (error: any) { setNotice(error?.response?.data?.error || 'Workspace details could not be loaded.'); }
    finally { setBusy(false); }
  }
  async function renewAndCopyLink(link: Row) {
    setBusy(true);
    try {
      const response = await post('/api/super-admin/registration-links/refresh', { id: link.id });
      const url = String(response.data.link.url);
      setLinkUrls((old) => ({ ...old, [link.id]: url }));
      try {
        await navigator.clipboard.writeText(url);
        setNotice('A fresh registration link was generated and copied. The previous URL is now invalid.');
      } catch {
        setNotice('A fresh registration link was generated. Clipboard access is unavailable; copy the displayed URL below.');
      }
      await load();
    } catch (error: any) {
      const message = error?.response?.data?.error || error?.message || 'Registration link could not be renewed.';
      if (error?.response?.status === 409 || error?.response?.status === 404) await load();
      setNotice(message);
    } finally { setBusy(false); }
  }
  async function revokeLink(link: Row) {
    if (!window.confirm('Revoke this unused registration link?')) return;
    setBusy(true);
    try { await post('/api/super-admin/registration-links/revoke', { id: link.id }); await load(); setNotice('Registration link revoked.'); }
    catch (error: any) {
      const message = error?.response?.data?.error || error?.message || 'Registration link could not be revoked.';
      if (error?.response?.status === 409 || error?.response?.status === 404) await load();
      setNotice(message);
    }
    finally { setBusy(false); }
  }
  const copy = async (value: string, label: string) => {
    try { await navigator.clipboard.writeText(value); setNotice(label + ' copied.'); }
    catch { setNotice('Clipboard access was unavailable. Select and copy the displayed link.'); }
  };

  const stats = [
    { label: 'Registered shops', value: data.stats?.shops || 0, icon: Store },
    { label: 'Active workspaces', value: data.stats?.activeShops || 0, icon: Building2 },
    { label: 'Pending applications', value: data.stats?.pendingApplications || 0, icon: FileCheck2 },
    { label: 'Managing Directors', value: data.stats?.managingDirectors || 0, icon: Users },
    { label: 'Platform sales volume', value: money(data.stats?.platformRevenue || 0), icon: Wallet }
  ];

  return <div className="sa-shell">
    <aside className="sa-sidebar">
      <div className="sa-brand"><span><ShieldCheck size={21}/></span><div><b>ShopFlow</b><small>PLATFORM CONTROL</small></div></div>
      <div className="sa-admin"><span>{String(user.name || 'A').slice(0,1).toUpperCase()}</span><div><b>{user.name}</b><small>Super Admin</small></div></div>
      <small className="sa-nav-label">PLATFORM MANAGEMENT</small>
      {[
        ['overview','Overview',Activity],['alerts','Registration alerts',Bell],['applications','Registration applications',FileCheck2],['workspaces','Business workspaces',Store],['links','Registration links',Link2]
      ].map(([key,label,Icon]: any) => <button key={key} className={tab === key ? 'active' : ''} onClick={() => { setTab(key); setQuery(''); }}><Icon size={17}/>{label}</button>)}
      <div className="sa-sidebar-bottom"><span><ShieldCheck size={15}/> Platform-wide access</span><button onClick={onLogout}><LogOut size={16}/> Sign out</button></div>
    </aside>
    <main className="sa-main">
      <header className="sa-header"><div><small>SHOPFLOW PLATFORM / {tab.toUpperCase()}</small><h1>{tab === 'overview' ? 'Platform overview' : tab === 'alerts' ? 'Registration alerts' : tab === 'applications' ? 'Registration applications' : tab === 'workspaces' ? 'Business workspaces' : 'Registration links'}</h1></div><div className="sa-header-actions"><button className="sa-refresh" disabled={pushBusy} onClick={() => void enablePushAlerts()}><Bell size={15}/>{pushBusy ? 'Enabling…' : 'Enable push alerts'}</button><button className="sa-refresh" disabled={busy} onClick={() => void load()}><RefreshCw size={15}/> Refresh</button></div></header>
      <div className="sa-content">
        {notice && <div className="sa-notice"><CircleAlert size={16}/><span>{notice}</span><button onClick={() => setNotice('')}><X size={15}/></button></div>}
        {claimUrl && <section className="sa-claim"><div><b>One-time link ready</b><small>Share securely with the intended business owner. It expires after seven days.</small><input readOnly value={claimUrl}/></div><button onClick={() => void copy(claimUrl, 'Claim link')}><Copy size={15}/> Copy link</button><button className="sa-dismiss" onClick={() => setClaimUrl('')}><X size={15}/></button></section>}
        {tab === 'overview' && <>
          <section className="sa-welcome"><div><span>PLATFORM-WIDE ADMINISTRATION</span><h2>Manage every ShopFlow workspace.</h2><p>Issue controlled registration links, review business applications, approve Managing Director account claims and govern workspace access.</p></div><button onClick={() => setTab('links')}><Link2 size={16}/> Create registration link</button></section>
          <div className="sa-stat-grid">{stats.map(item => <article key={item.label}><span><item.icon size={18}/></span><small>{item.label}</small><b>{item.value}</b></article>)}</div>
          <div className="sa-overview-grid"><section className="sa-panel"><div className="sa-panel-head"><div><h3>Applications requiring review</h3><p>Business owners who submitted through an issued link.</p></div><button onClick={() => setTab('applications')}>View all <ChevronRight size={14}/></button></div>{(data.applications || []).filter((x: Row) => ['submitted','under_review'].includes(x.status)).slice(0,5).map((x: Row) => <div className="sa-list-row" key={x.id}><div><b>{x.shopName}</b><small>{x.ownerName} · {x.email}</small></div><span className="sa-status pending">{x.status}</span></div>)}{!data.stats?.pendingApplications && <p className="sa-empty">No pending applications.</p>}</section>
          <section className="sa-panel"><div className="sa-panel-head"><div><h3>Workspace status</h3><p>Latest registered shops.</p></div><button onClick={() => setTab('workspaces')}>View all <ChevronRight size={14}/></button></div>{(data.workspaces || []).slice(0,5).map((x: Row) => <div className="sa-list-row" key={x.id}><div><b>{x.name}</b><small>{x.managingDirector?.email || 'Managing Director not claimed'}</small></div><span className={'sa-status '+(x.status === 'suspended' ? 'suspended' : 'active')}>{x.status}</span></div>)}{!data.workspaces?.length && <p className="sa-empty">No approved workspaces yet.</p>}</section></div>
        </>}
        {tab === 'alerts' && <section className="sa-panel"><div className="sa-panel-head"><div><h3>Shop registration alerts</h3><p>New applications are recorded here and sent to subscribed Super Admin devices.</p></div><span className="sa-status pending">{data.stats?.unreadNotifications || 0} unread</span></div>{(data.notifications || []).map((item: Row) => <div className="sa-list-row" key={item.id}><div><b>{item.title}</b><small>{item.body} · {date(item.createdAt)}</small></div>{item.readAt ? <span className="sa-status">Read</span> : <button className="sa-doc-link" onClick={() => void markNotificationRead(item)}>Mark as read</button>}</div>)}{!data.notifications?.length && <p className="sa-empty">No registration alerts have been received yet.</p>}</section>}
        {tab === 'applications' && <section className="sa-panel"><div className="sa-panel-head"><div><h3>Business registration queue</h3><p>Approval creates a disabled Managing Director account and a one-time claim link.</p></div><label className="sa-search"><Search size={15}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search applicants or shops"/></label></div>
          <div className="sa-table-wrap"><table><thead><tr><th>Submitted</th><th>Business / owner</th><th>Track</th><th>Contact</th><th>Verification</th><th>Evidence</th><th>Status</th><th>Decision</th></tr></thead><tbody>{applications.map((x: Row) => <tr key={x.id}><td>{date(x.submittedAt)}</td><td><b>{x.shopName}</b><small>{x.ownerName}</small></td><td>{x.track === 'formal' ? 'Registered business' : 'Individual retailer'}</td><td>{x.email}<small>{x.phone}</small></td><td><small>Identity: {x.identityStatus}</small><small>Payout: {x.payoutVerificationStatus}</small><small>Business: {x.businessStatus}</small></td><td>{(x.documents || []).map((document: Row) => <button key={document.kind} className="sa-doc-link" onClick={() => void openApplicationDocument(x,document)}><ExternalLink size={12}/>{document.kind.replace(/_/g,' ')}</button>)}{!x.documents?.length && '—'}</td><td><span className={'sa-status '+(x.status === 'rejected' ? 'suspended' : x.status === 'approved' || x.status === 'account_claimed' ? 'active' : 'pending')}>{x.status}</span></td><td>{['submitted','under_review'].includes(x.status) ? <div className="sa-actions"><button disabled={busy} onClick={() => void decide(x,'approve')}><Check size={14}/> Approve</button><button className="danger" disabled={busy} onClick={() => { setRejecting(x); setRejectReason(''); }}><X size={14}/> Reject</button></div> : x.status === 'approved' ? <span>Awaiting claim</span> : '—'}</td></tr>)}</tbody></table></div>
          {rejecting && <div className="sa-reject"><b>Reject {rejecting.shopName}</b><input value={rejectReason} onChange={e => setRejectReason(e.target.value)} placeholder="Reason for rejection"/><button className="danger" disabled={busy} onClick={() => void decide(rejecting,'reject')}>Confirm rejection</button><button onClick={() => setRejecting(null)}>Cancel</button></div>}
          {!applications.length && <p className="sa-empty">No applications have been submitted.</p>}
        </section>}
        {tab === 'workspaces' && <section className="sa-panel"><div className="sa-panel-head"><div><h3>All business workspaces</h3><p>Platform-wide workspace access and operational overview.</p></div><label className="sa-search"><Search size={15}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search shops or Managing Directors"/></label></div>
          <div className="sa-table-wrap"><table><thead><tr><th>Shop</th><th>Managing Director</th><th>Staff</th><th>Products</th><th>Sales</th><th>Sales value</th><th>Status</th><th>Control</th></tr></thead><tbody>{workspaces.map((x: Row) => <tr key={x.id}><td><b>{x.name}</b><small>Created {date(x.createdAt)}</small></td><td>{x.managingDirector?.name || 'Not claimed'}<small>{x.managingDirector?.email || ''}</small></td><td>{x.staffCount}</td><td>{x.productCount}</td><td>{x.salesCount}</td><td>{money(x.revenue)}</td><td><span className={'sa-status '+(x.status === 'suspended' ? 'suspended' : 'active')}>{x.status}</span></td><td><div className="sa-actions"><button onClick={() => void inspectWorkspace(x)}>Inspect</button><button className={x.status === 'suspended' ? '' : 'danger'} disabled={busy} onClick={() => void changeWorkspaceStatus(x)}>{x.status === 'suspended' ? 'Reactivate' : 'Suspend'}</button></div></td></tr>)}</tbody></table></div>
          {!workspaces.length && <p className="sa-empty">No business workspaces have been approved yet.</p>}
        </section>}
        {tab === 'links' && <div className="sa-links-grid"><section className="sa-panel"><div className="sa-panel-head"><div><h3>Issue a shop registration link</h3><p>Each link can submit one application and expires automatically.</p></div></div><label>Link expiry<select value={expiry} onChange={e => setExpiry(e.target.value)}><option value="1">1 day</option><option value="3">3 days</option><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option></select></label><button className="sa-primary" disabled={busy} onClick={() => void createLink()}><Link2 size={15}/> Generate secure registration link</button></section><section className="sa-panel"><div className="sa-panel-head"><div><h3>Issued registration links</h3><p>Unused link tokens are stored as hashes. Renew an unused link to generate a fresh copyable URL; this invalidates its previous URL.</p></div></div>{links.map((link: Row) => <div className="sa-link-card" key={link.id}><div className="sa-link-row"><div><b>{link.id}</b><small>Expires {date(link.expiresAt)}</small><span className={'sa-status '+(link.status === 'available' ? 'active' : link.status === 'used' ? 'pending' : 'suspended')}>{link.status}</span></div>{link.status === 'available' && <div className="sa-link-actions"><button disabled={busy} onClick={() => void renewAndCopyLink(link)}><Copy size={13}/> Renew &amp; copy</button><button className="danger" disabled={busy} onClick={() => void revokeLink(link)}>Revoke</button></div>}</div>{linkUrls[link.id] && <div className="sa-link-copy"><input aria-label="Renewed registration URL" readOnly value={linkUrls[link.id]}/><button onClick={() => void copy(linkUrls[link.id], 'Registration link')}><Copy size={13}/> Copy again</button></div>}</div>)}{!links.length && <p className="sa-empty">No registration links issued.</p>}</section></div>}
      </div>
    </main>
    {selected && <div className="sa-detail-backdrop" onMouseDown={e => { if (e.target === e.currentTarget) setSelected(null); }}><section className="sa-detail"><header><div><small>WORKSPACE CONTROL</small><h2>{selected.workspace?.name || 'Shop details'}</h2></div><button onClick={() => setSelected(null)}><X/></button></header><div className="sa-detail-grid"><article><small>Status</small><b>{selected.workspace?.status}</b></article><article><small>Marketplace</small><b>{selected.workspace?.marketplaceEnabled ? 'Enabled' : 'Disabled'}</b></article><article><small>Products</small><b>{selected.metrics?.products || 0}</b></article><article><small>Sales</small><b>{selected.metrics?.sales || 0}</b></article><article><small>Sales value</small><b>{money(selected.metrics?.revenue || 0)}</b></article><article><small>Open orders</small><b>{selected.metrics?.pendingOrders || 0}</b></article></div><h3>Managing Director</h3><p>{selected.managingDirector?.name || 'Not claimed'} · {selected.managingDirector?.email || '—'}</p><h3>Workspace users</h3>{(selected.staff || []).map((x: Row) => <div className="sa-list-row" key={x.id}><div><b>{x.name}</b><small>{x.email} · {x.role}</small></div><span>{x.active === false ? 'Disabled' : 'Active'}</span></div>)}<h3>Payout destinations</h3>{(selected.payoutProfiles || []).map((x: Row) => <div className="sa-list-row" key={x.id}><div><b>{x.payoutType} · {x.accountName}</b><small>{x.provider} · ending {x.accountNumberLast4}</small></div><span>{x.verificationStatus}</span></div>)}</section></div>}
  </div>;
}
