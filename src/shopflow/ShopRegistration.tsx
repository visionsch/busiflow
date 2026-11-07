// @ts-nocheck
import { useState } from 'react';
import { api } from './shims/client';
import { ArrowLeft, ArrowRight, Building2, CheckCircle2, FileText, ShieldCheck, Store, X } from 'lucide-react';

const categories = ['General retail','Fashion','Electronics','Food and groceries','Health and beauty','Building materials','Wholesale','Other'];
const regions = ['Ahafo','Ashanti','Bono','Bono East','Central','Eastern','Greater Accra','North East','Northern','Oti','Savannah','Upper East','Upper West','Volta','Western','Western North'];
const readFile = (file: File) => new Promise<string>((resolve, reject) => {
  const reader = new FileReader();
  reader.onload = () => { const value = String(reader.result || ''); resolve(value.slice(value.indexOf(',') + 1)); };
  reader.onerror = () => reject(new Error('Could not read file.'));
  reader.readAsDataURL(file);
});

export default function ShopRegistration({ open, onClose }: { open: boolean; onClose: () => void }) {
  const query = new URLSearchParams(window.location.search);
  const registrationToken = query.get('shopRegistration') || '';
  const claimToken = query.get('claim') || '';
  const [step, setStep] = useState(0);
  const [track, setTrack] = useState('individual');
  const [files, setFiles] = useState<any[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState<any>(null);
  const [claimDone, setClaimDone] = useState('');
  const [claimForm, setClaimForm] = useState({ password: '', confirmPassword: '' });
  const [values, setValues] = useState<any>({
    ownerName:'', email:'', phone:'', shopName:'', category:'', region:'Greater Accra',
    district:'', town:'', address:'', businessName:'', registrationNumber:'', businessTin:'',
    ghanaCardNumber:'', payoutType:'personal_momo', bankName:'', network:'MTN',
    accountName:'', accountNumber:'', identityConsent:false, termsAccepted:false
  });
  if (!open) return null;
  const set = (key: string, value: any) => setValues((old: any) => ({ ...old, [key]: value }));
  const requiredDocuments = track === 'formal' ? ['registration_certificate','business_tin_document'] : [];
  const field = (label: string, key: string, type = 'text') => <label>{label} *<input type={type} value={values[key]} onChange={event => set(key, event.target.value)} /></label>;

  const upload = async (kind: string, file?: File) => {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024 || !['application/pdf','image/jpeg','image/png'].includes(file.type)) {
      setError('PDF, JPG or PNG files up to 2 MB only.');
      return;
    }
    try {
      const data = await readFile(file);
      setFiles(old => [...old.filter(item => item.kind !== kind), { kind, name:file.name, contentType:file.type, data }]);
      setError('');
    } catch { setError('The selected document could not be read.'); }
  };

  const validate = () => {
    setError('');
    if (step === 0 && (!values.ownerName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email) || !/^0[0-9]{9}$/.test(values.phone.replace(/\D/g,'')))) {
      setError('Enter a valid owner name, email address and Ghana mobile number.'); return false;
    }
    if (step === 1 && (!values.shopName || !values.category || !values.district || !values.town || !values.address)) {
      setError('Complete the required shop location and business details.'); return false;
    }
    if (step === 2 && ((track === 'formal' && (!values.businessName || !values.registrationNumber || !values.businessTin)) || requiredDocuments.some(kind => !files.some(file => file.kind === kind)) || (track === 'individual' && !/^GHA-[0-9]{9}-[0-9]$/.test(values.ghanaCardNumber.toUpperCase())) || !values.identityConsent)) {
      setError('Complete the seller verification details, Ghana Card number or required business evidence.'); return false;
    }
    if (step === 3 && (!values.accountName || !values.accountNumber || (values.payoutType === 'corporate_bank' && !values.bankName) || (track === 'individual' && values.payoutType !== 'personal_momo'))) {
      setError('Complete the permitted payout destination.'); return false;
    }
    return true;
  };

  const submit = async () => {
    if (!registrationToken) { setError('A valid ShopFlow registration link is required. Contact the platform administrator.'); return; }
    if (!values.termsAccepted) { setError('Confirm the accuracy of your application before submitting.'); return; }
    setBusy(true);
    try {
      const response = await api.post('/api/onboarding/applications', { ...values, track, registrationToken, documents: files });
      setDone(response.data);
    } catch (reason: any) {
      setError(reason?.response?.data?.error || reason?.message || 'Registration could not be submitted.');
    } finally { setBusy(false); }
  };

  const claim = async () => {
    if (!claimToken) { setError('Open the one-time account claim link supplied by ShopFlow.'); return; }
    if (claimForm.password.length < 8 || claimForm.password !== claimForm.confirmPassword || !/[A-Z]/.test(claimForm.password) || !/[a-z]/.test(claimForm.password) || !/[0-9]/.test(claimForm.password) || !/[^A-Za-z0-9]/.test(claimForm.password)) {
      setError('Use matching passwords with uppercase, lowercase, a number, a special character and at least eight characters.'); return;
    }
    setBusy(true);
    try {
      const response = await api.post('/api/onboarding/claim', { claimToken, password: claimForm.password, confirmPassword: claimForm.confirmPassword });
      setClaimDone(response.data.message || 'Account claimed. You can now sign in.');
    } catch (reason: any) {
      setError(reason?.response?.data?.error || reason?.message || 'Account claim failed.');
    } finally { setBusy(false); }
  };

  return <div className="sf-reg-overlay">
    <section className="sf-reg-dialog" role="dialog" aria-modal="true">
      <header><b>ShopFlow · Business registration</b><button onClick={onClose}><X/></button></header>
      {claimToken ? <div className="sf-reg-result">
        {claimDone ? <><CheckCircle2/><h2>Account activated</h2><p>{claimDone}</p><button onClick={onClose}>Continue to sign in</button></> : <>
          <ShieldCheck/><h2>Claim Managing Director account</h2><p>Your shop registration has been approved. Set a secure password to activate your Managing Director account.</p>
          <label>Password<input type="password" autoComplete="new-password" value={claimForm.password} onChange={event => setClaimForm({ ...claimForm, password:event.target.value })}/></label>
          <label>Confirm password<input type="password" autoComplete="new-password" value={claimForm.confirmPassword} onChange={event => setClaimForm({ ...claimForm, confirmPassword:event.target.value })}/></label>
          {error && <p className="sf-error">{error}</p>}
          <button disabled={busy} onClick={() => void claim()}>{busy ? 'Activating…' : 'Activate Managing Director account'}</button>
        </>}
      </div> : !registrationToken ? <div className="sf-reg-result">
        <Store/><h2>Registration link required</h2>
        <p>ShopFlow business owners must contact the platform workspace administrator to request a secure, one-time shop registration link. Managing Director accounts are created only after the Super Admin approves the application.</p>
        <button onClick={onClose}>Close</button>
      </div> : done ? <div className="sf-reg-result">
        <CheckCircle2/><h2>Application submitted</h2><b>{done.application?.reference}</b>
        <p>{done.message}</p><button onClick={onClose}>Close</button>
      </div> : <>
        <div className="sf-reg-heading"><small>SECURE, INVITATION-ONLY ONBOARDING</small><h1>Register your business workspace</h1><p>Step {step + 1} of 5 · {['Owner contact','Shop details','Business verification','Payout destination','Review'][step]}</p></div>
        <main>
          {step === 0 && <>{field('Managing Director full name','ownerName')}{field('Email address','email','email')}{field('Ghana mobile number','phone')}</>}
          {step === 1 && <>{field('Shop / business name','shopName')}<label>Category *<select value={values.category} onChange={event => set('category',event.target.value)}><option value="">Select</option>{categories.map(item => <option key={item}>{item}</option>)}</select></label><label>Region *<select value={values.region} onChange={event => set('region',event.target.value)}>{regions.map(item => <option key={item}>{item}</option>)}</select></label>{field('District','district')}{field('Town / city','town')}<label>Physical address *<textarea value={values.address} onChange={event => set('address',event.target.value)}/></label></>}
          {step === 2 && <>
            <div className="sf-track-grid"><button className={track === 'formal' ? 'chosen' : ''} onClick={() => { setTrack('formal'); set('payoutType','corporate_bank'); }}><Building2/> Track A · Registered business</button><button className={track === 'individual' ? 'chosen' : ''} onClick={() => { setTrack('individual'); set('payoutType','personal_momo'); }}><Store/> Track B · Individual retailer</button></div>
            {track === 'formal' ? <>{field('Registered legal business name','businessName')}{field('Business registration number','registrationNumber')}{field('Business TIN','businessTin')}{requiredDocuments.map(kind => <label className="sf-upload" key={kind}><FileText/>{kind.replace(/_/g,' ')}<input type="file" accept=".pdf,.jpg,.jpeg,.png" onChange={event => void upload(kind,event.target.files?.[0])}/><small>{files.find(file => file.kind === kind)?.name || 'Choose PDF, JPG or PNG'}</small></label>)}</> : <>{field('Ghana Card number','ghanaCardNumber')}<div className="sf-info">The Ghana Card number is encrypted before persistence. Identity verification and name matching remain pending until an approved verification provider confirms the record.</div></>}
            <label className="sf-consent"><input type="checkbox" checked={values.identityConsent} onChange={event => set('identityConsent',event.target.checked)}/>I consent to identity, business and payout beneficiary verification.</label>
          </>}
          {step === 3 && <>{track === 'formal' ? <label>Payout destination *<select value={values.payoutType} onChange={event => set('payoutType',event.target.value)}><option value="corporate_bank">Corporate bank account</option><option value="business_momo">Registered business MoMo wallet</option></select></label> : <p>Individual retailers may use verified personal Mobile Money only.</p>}
            {values.payoutType === 'corporate_bank' ? <><label>Bank *<select value={values.bankName} onChange={event => set('bankName',event.target.value)}><option value="">Select bank</option>{['Ecobank Ghana','Zenith Bank Ghana','GCB Bank','Absa Bank Ghana','Stanbic Bank Ghana','Fidelity Bank Ghana','Other'].map(item => <option key={item}>{item}</option>)}</select></label>{field('Corporate account number','accountNumber')}</> : <><label>Mobile Money network *<select value={values.network} onChange={event => set('network',event.target.value)}><option>MTN</option><option>Telecel</option><option>AT</option></select></label>{field('Mobile Money number','accountNumber')}</>}
            {field('Beneficiary registered account name','accountName')}<div className="sf-info">Payout details are encrypted. Hubtel account-name verification is performed during Super Admin review before payout activation.</div>
          </>}
          {step === 4 && <><h2>Review application</h2><p>{values.ownerName} · {values.email} · {values.phone}</p><p>{values.shopName} · {values.category} · {values.region}, {values.district}</p><p>{track === 'formal' ? 'Registered business' : 'Individual retailer'} · {values.payoutType}</p><p>{values.accountName} · account ending {values.accountNumber.slice(-4)}</p><label className="sf-consent"><input type="checkbox" checked={values.termsAccepted} onChange={event => set('termsAccepted',event.target.checked)}/>I confirm these details are accurate and accept ShopFlow's registration and privacy terms.</label></>}
          {error && <p className="sf-error">{error}</p>}
        </main>
        <footer><button onClick={() => step ? setStep(step - 1) : onClose()}><ArrowLeft/> Back</button>{step < 4 ? <button onClick={() => { if (validate()) setStep(step + 1); }}>Continue <ArrowRight/></button> : <button disabled={busy || !values.termsAccepted} onClick={() => void submit()}>{busy ? 'Submitting…' : 'Submit for Super Admin approval'} <ShieldCheck/></button>}</footer>
      </>}
    </section>
  </div>;
}
