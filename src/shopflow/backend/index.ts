// @ts-nocheck
import { router, json, db, secrets, storage, isAppDatabaseError } from '../shims/sdk';
import webpush from 'web-push';
import { Pool } from 'pg';

type User = { id?:string; name:string; email:string; passwordHash:string; role:string; active:boolean; createdAt:string; ownerId:string; avatarUrl?:string };
type Session = { userId:string; csrfToken:string; expiresAt:number };
type Product = { id?:string; name:string; sku:string; barcode:string; category:string; price:number; cost:number; stock:number; reorderLevel:number; imageUrl?:string; imageGallery?:(string|{view:string;url:string})[]; brand?:string; model?:string; condition?:string; color?:string; size?:string; material?:string; warranty?:string; features?:string; specifications?:string; description?:string; updatedAt:string; ownerId:string };
type Sale = { number:string; items:{productId:string;name:string;qty:number;price:number}[]; total:number; payment:string; customer:string; createdAt:string; ownerId:string; agentName:string };
type Supplier = { id?:string; name:string; contact:string; email:string; phone:string; address:string; taxId:string; ownerId:string; createdAt:string };
type Purchase = { number:string; supplierId:string; supplierName:string; productId:string; productName:string; qty:number; unitCost:number; total:number; status:string; expectedDate:string; ownerId:string; createdAt:string };
type Expense = { description:string; category:string; amount:number; date:string; payment:string; actorName:string; ownerId:string; createdAt:string };
type Invoice = { number:string; customer:string; customerPhone:string; description:string; qty:number; unitPrice:number; total:number; status:string; dueDate:string; ownerId:string; createdAt:string };
type Customer = { name:string; phone:string; visits:number; lifetimeValue:number; ownerId:string };
type StockMove = { productId:string; productName:string; type:string; qty:number; reason:string; actorName:string; ownerId:string; createdAt:string };
const roles = ['Managing Director','General Manager','Sales Agent','Warehouse Manager','Procurement Officer','Accountant','Auditor'];
const SHOP_IDENTITY_DEFAULT='ShopFlow';
function resolveShopIdentity(configuration:any,ownerId:string){const configuredName=typeof configuration?.storeName==='string'?configuration.storeName.trim():'';return{ownerId,shopName:configuredName||SHOP_IDENTITY_DEFAULT,tagline:String(configuration?.tagline||''),city:String(configuration?.city||''),description:String(configuration?.description||'')}}
async function getShopIdentity(ownerId:string){const[configuration]=await db.get<any>('marketplace_settings',[ownerId],{consistent:true});const[workspace]=await db.get<any>('marketplace_settings',['workspace_'+ownerId],{consistent:true});return resolveShopIdentity(configuration||{storeName:workspace?.displayName},ownerId)}
function storedProductImagePath(value:string,ownerId:string){const prefix='storage://shops/'+ownerId+'/products/';return value.startsWith(prefix)&&value.length<=320&&/^storage:\/\/shops\/[A-Za-z0-9_-]+\/products\/[A-Za-z0-9._-]+$/.test(value)}
async function resolveProductImage(value:string,ownerId:string){if(!storedProductImagePath(value,ownerId))return value||'';const path=value.slice('storage://'.length);const[entry]=await storage.url([path]);return entry?.url||''}
function storedProfileImagePath(value:string,ownerId:string,userId:string){const prefix='storage://shops/'+ownerId+'/profiles/'+userId+'/';return value.startsWith(prefix)&&value.length<=420&&/^[A-Za-z0-9._-]{1,120}$/.test(value.slice(prefix.length))}
async function resolveProfileImage(value:string,ownerId:string,userId:string){if(storedProfileImagePath(value,ownerId,userId)){const[entry]=await storage.url([value.slice('storage://'.length)]);return entry?.url||''}return value.startsWith('https://')?value:''}
const grants:Record<string,string[]> = {'Super Admin':['platform'],'Managing Director':['*'],'General Manager':['overview','sales','products','stock','suppliers','purchases','expenses','invoices','customers','reports','team:read','online-orders'],'Sales Agent':['overview','sales','invoices','customers','online-orders'],'Warehouse Manager':['overview','products','stock','suppliers','purchases','online-orders'],'Procurement Officer':['overview','products','suppliers','purchases','stock'],'Accountant':['overview','sales','expenses','invoices','reports','customers'],'Auditor':['overview','sales:read','products:read','stock:read','suppliers:read','purchases:read','expenses:read','invoices:read','customers:read','reports']};
const COOKIE='shopflow_session',TTL=7*24*60*60*1000,enc=new TextEncoder();
function headers(e:any){const o:Record<string,string>={};for(const[k,v]of Object.entries(e?.headers||{}))if(typeof v==='string')o[k.toLowerCase()]=v;return o}
function cookie(h:Record<string,string>){return(h.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)}
function setCookie(v:string,age:number){return COOKIE+'='+v+'; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age='+age}
function res(statusCode:number,data:unknown,extra:Record<string,string>={}){return{statusCode,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'strict-origin-when-cross-origin',...extra},body:JSON.stringify(data)}}
function bad(message:string,status=400){return res(status,{error:message})}
function hasState(value:unknown){return value!==null&&value!==undefined&&String(value).trim()!==''}
function registrationLinkStatus(link:any,now=Date.now()){
 if(hasState(link?.revokedAt))return 'revoked';
 if(hasState(link?.usedAt))return 'used';
 const expiry=Date.parse(String(link?.expiresAt||''));
 if(!Number.isFinite(expiry)||expiry<=now)return 'expired';
 return 'available';
}
function token(n=32){const a=new Uint8Array(n);crypto.getRandomValues(a);return Array.from(a,b=>b.toString(16).padStart(2,'0')).join('')}
function origin(h:Record<string,string>,e:any){try{const host=(h['x-forwarded-host']||h.host||e?.requestContext?.domainName||'').split(',')[0].trim();if(!host)return null;const proto=(h['x-forwarded-proto']||'https').split(',')[0].trim();return new URL(proto+'://'+host).origin}catch{return null}}
let SHOPFLOW_PUBLIC_ORIGIN = 'https://shopflow-manager-xdwpp8.v2.appdeploy.ai';
function safe(ctx:any){const h=headers(ctx.event),site=h['sec-fetch-site'],ct=(h['content-type']||'').toLowerCase();if(site==='cross-site')return false;if(site&& !['same-origin','same-site','none'].includes(site))return false;try{const supplied=h.origin?new URL(h.origin):null,referer=h.referer?new URL(h.referer):null;if(supplied&&supplied.protocol!=='https:')return false;if(referer&&referer.protocol!=='https:')return false;if(supplied&&referer&&supplied.origin!==referer.origin)return false;if(supplied||referer||site==='same-origin'||site==='same-site')return true;return ct.startsWith('application/json')}catch{return false}}
function unsafe(ctx:any){const m=String(ctx.event?.httpMethod||ctx.event?.requestContext?.http?.method||'').toUpperCase();return ['GET','HEAD','OPTIONS'].includes(m)||safe(ctx)}
function obj<T>(v:unknown){return(v&&typeof v==='object'?v:{}) as T}
async function hash(p:string,s=token(16)){const key=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(s),iterations:210000,hash:'SHA-256'},key,256);return 'pbkdf2:'+s+':'+Array.from(new Uint8Array(bits),b=>b.toString(16).padStart(2,'0')).join('')}
async function verify(p:string,saved:string){const parts=saved.split(':');if(parts[0]==='pbkdf2'&&parts[1]&&parts[2]){const expected=parts[2],actual=(await hash(p,parts[1])).split(':')[2];let d=actual.length^expected.length;for(let i=0;i<Math.min(actual.length,expected.length);i++)d|=actual.charCodeAt(i)^expected.charCodeAt(i);return d===0}const[s,w]=parts;if(!s||!w)return false;let v=enc.encode(s+':'+p);for(let i=0;i<120000;i++)v=new Uint8Array(await crypto.subtle.digest('SHA-256',v));const g=Array.from(v,b=>b.toString(16).padStart(2,'0')).join('');let d=g.length^w.length;for(let i=0;i<Math.min(g.length,w.length);i++)d|=g.charCodeAt(i)^w.charCodeAt(i);return d===0}
async function all<T extends Record<string,any>>(table:string){const r=await db.list<T>(table,{limit:500});if(r.nextToken)throw new Error('PAGINATION_REQUIRED: '+table+' contains more than 500 records; use a cursor-based endpoint rather than silently truncating the result.');return r.items}
async function find<T extends Record<string,any>>(table:string,field:string,value:string){return(await all<T>(table)).filter(x=>String(x[field]||'').toLowerCase()===value.toLowerCase())}
async function owned<T extends Record<string,any>>(table:string,ownerId:string){return(await all<T>(table)).filter(x=>x.ownerId===ownerId)}
async function session(ctx:any,csrf=true){const h=headers(ctx.event),id=cookie(h);if(!id)return null;const[s]=await db.get<Session>('sessions',[id]);if(!s||s.expiresAt<Date.now())return null;if(csrf){const b=obj<{_csrf?:string}>(ctx.body),given=h['x-csrf-token']||b._csrf;if(!given||given!==s.csrfToken)return null}const[u]=await db.get<User>('users',[s.userId]);if(!u||u.active===false)return null;if(u.role!=='Super Admin'&&u.ownerId){const[workspace]=await db.get<any>('marketplace_settings',['workspace_'+u.ownerId],{consistent:true});if(workspace?.status==='suspended')return null;}return{userId:s.userId,sessionId:id,csrfToken:s.csrfToken,user:{...u,id:s.userId}}}
function permit(s:any,key:string,write=true){if(!s)return false;const g=grants[s.user.role]||[];return g.includes('*')||g.includes(key)&&write||!write&&(g.includes(key+':read')||g.includes(key))}
function guard(ctx:any,s:any,key:string,write=true){if(!unsafe(ctx))return bad('Cross-site request rejected.',403);if(!s)return bad('Session or CSRF token is invalid.',403);if(!permit(s,key,write))return bad('Your role does not have permission for this action.',403);return null}
function clean<T extends Record<string,any>>(items:T[]){return items.map(({ownerId,passwordHash,...x})=>x)}
async function create(table:string,record:Record<string,unknown>){const[ id ]=await db.add(table,[record]);return id}
async function setRecord(table:string,id:string,record:Record<string,unknown>){const[ok]=await db.update(table,[{id,record}]);return ok}
async function getRegistrationLink(id:string){const[direct]=await db.get<any>('shop_registration_links',[id],{consistent:true});if(direct)return direct;return(await all<any>('shop_registration_links')).find(item=>String(item.id||'')===id)||null}
function validPassword(password:string){return password.length>=8&&password.length<=128&&/[A-Z]/.test(password)&&/[a-z]/.test(password)&&/[0-9]/.test(password)&&/[^A-Za-z0-9]/.test(password)}
function isPersistedAccount(user:any){return !!user&&typeof user.name==='string'&&user.name.trim().length>=2&&typeof user.email==='string'&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user.email)&&typeof user.passwordHash==='string'&&user.passwordHash.length>=20&&typeof user.role==='string'&&user.role.trim().length>0}
function num(v:any){return Number.isFinite(Number(v))?Number(v):NaN}
function normalizeGhanaPhone(value:any){
 let digits=String(value??'').replace(/[^0-9]/g,'');
 if(digits.startsWith('00233'))digits=digits.slice(2);
 if(/^0[0-9]{9}$/.test(digits))return '233'+digits.slice(1);
 if(/^233[0-9]{9}$/.test(digits))return digits;
 return '';
}
function docNo(prefix:string){return prefix+'-'+Date.now().toString(36).toUpperCase()+'-'+token(3).toUpperCase()}
async function encryptMtnCredentials(value:string, secret:string){
 const digest=await crypto.subtle.digest('SHA-256',enc.encode(secret));
 const key=await crypto.subtle.importKey('raw',digest,{name:'AES-GCM'},false,['encrypt']);
 const iv=crypto.getRandomValues(new Uint8Array(12));
 const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(value));
 const hex=(bytes:Uint8Array)=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 return {iv:hex(iv),ciphertext:hex(new Uint8Array(cipher))};
}
async function decryptMtnCredentials(record:any, secret:string){
 const digest=await crypto.subtle.digest('SHA-256',enc.encode(secret));
 const key=await crypto.subtle.importKey('raw',digest,{name:'AES-GCM'},false,['decrypt']);
 const bytes=(hex:string)=>new Uint8Array(hex.match(/.{2}/g)?.map(x=>parseInt(x,16))||[]);
 const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(record.iv)},key,bytes(record.ciphertext));
 return new TextDecoder().decode(plain);
}
async function encryptWorkspacePaymentCredentials(value:string,masterKey:string,workspaceId:string,credentialId:string){
 const digest=await crypto.subtle.digest('SHA-256',enc.encode(masterKey));
 const key=await crypto.subtle.importKey('raw',digest,{name:'AES-GCM'},false,['encrypt']);
 const iv=crypto.getRandomValues(new Uint8Array(12)),additionalData=enc.encode(workspaceId+':'+credentialId);
 const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData},key,enc.encode(value));
 const hex=(bytes:Uint8Array)=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 return{iv:hex(iv),ciphertext:hex(new Uint8Array(cipher)),keyVersion:1};
}
async function decryptWorkspacePaymentCredentials(record:any,masterKey:string,workspaceId:string,credentialId:string){
 if(record?.workspaceId!==workspaceId||record?.id!==credentialId||record?.keyVersion!==1)throw new Error('workspace_payment_credential_binding_invalid');
 const digest=await crypto.subtle.digest('SHA-256',enc.encode(masterKey));
 const key=await crypto.subtle.importKey('raw',digest,{name:'AES-GCM'},false,['decrypt']);
 const bytes=(hex:string)=>new Uint8Array(hex.match(/.{2}/g)?.map((x:string)=>parseInt(x,16))||[]);
 const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(record.iv),additionalData:enc.encode(workspaceId+':'+credentialId)},key,bytes(record.ciphertext));
 return new TextDecoder().decode(plain);
}
async function mtnMerchantFingerprint(masterKey:string,subscriptionKey:string){const material=await crypto.subtle.digest('SHA-256',enc.encode('shopflow:merchant-identity:v1:'+masterKey));const key=await crypto.subtle.importKey('raw',material,{name:'HMAC',hash:'SHA-256'},false,['sign']);const signature=new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(subscriptionKey)));return Array.from(signature,b=>b.toString(16).padStart(2,'0')).join('')}
async function loadWorkspaceMtnCredentials(workspaceId:string,credentialId?:string){
 if(!/^[A-Za-z0-9_-]{1,120}$/.test(workspaceId))return null;
 const pointerId='mtn_workspace_'+workspaceId,[pointer]=await db.get<any>('integration_secrets',[pointerId],{consistent:true});
 if(!pointer||pointer.status!=='active'||pointer.workspaceId!==workspaceId||!pointer.activeCredentialId)return null;
 const selectedId=credentialId||pointer.activeCredentialId;
 const[record]=await db.get<any>('integration_secrets',[selectedId],{consistent:true});
 if(!record||record.workspaceId!==workspaceId||record.merchantAccountId!==pointer.merchantAccountId||record.status!=='active')return null;
 const names=await secrets.listSecretNames();
 if(!names.includes('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'))throw new Error('workspace_payment_encryption_key_missing');
 const masterKey=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY');
 if(masterKey.length<32)throw new Error('workspace_payment_encryption_key_invalid');
 const credentials=obj<{subscriptionKey?:string;apiUser?:string;apiKey?:string}>(JSON.parse(await decryptWorkspacePaymentCredentials(record,masterKey,workspaceId,selectedId)));
 if(!credentials.subscriptionKey||!credentials.apiUser||!credentials.apiKey)throw new Error('workspace_payment_credentials_incomplete');
 return{pointer,record,credentials,credentialId:selectedId,merchantAccountId:pointer.merchantAccountId};
}


async function loadWorkspacePaystackCredentials(workspaceId:string,credentialId?:string){
 if(!/^[A-Za-z0-9_-]{1,120}$/.test(workspaceId))return null;
 const pointerId='paystack_workspace_'+workspaceId,[pointer]=await db.get<any>('integration_secrets',[pointerId],{consistent:true});
 if(!pointer||pointer.status!=='active'||pointer.provider!=='PAYSTACK'||pointer.workspaceId!==workspaceId||!pointer.activeCredentialId)return null;
 const selectedId=credentialId||pointer.activeCredentialId;
 const[record]=await db.get<any>('integration_secrets',[selectedId],{consistent:true});
 if(!record||record.workspaceId!==workspaceId||record.merchantAccountId!==pointer.merchantAccountId||record.provider!=='PAYSTACK'||record.status!=='active')return null;
 const names=await secrets.listSecretNames();
 if(!names.includes('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'))throw new Error('workspace_payment_encryption_key_missing');
 const masterKey=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY');
 if(masterKey.length<32)throw new Error('workspace_payment_encryption_key_invalid');
 const credentials=obj<{secretKey?:string}>(JSON.parse(await decryptWorkspacePaymentCredentials(record,masterKey,workspaceId,selectedId)));
 if(!credentials.secretKey||!credentials.secretKey.startsWith('sk_live_'))throw new Error('workspace_paystack_credentials_incomplete');
 return{pointer,record,credentials,credentialId:selectedId,merchantAccountId:pointer.merchantAccountId};
}
async function getWorkspaceActivePaymentProvider(workspaceId:string){
 const [selection]=await db.get<any>('integration_secrets',['payment_provider_'+workspaceId],{consistent:true});
 const [mtn]=await db.get<any>('integration_secrets',['mtn_workspace_'+workspaceId],{consistent:true});
 const [paystack]=await db.get<any>('integration_secrets',['paystack_workspace_'+workspaceId],{consistent:true});
 const mtnReady=!!mtn&&mtn.status==='active'&&mtn.workspaceId===workspaceId&&!!mtn.activeCredentialId&&!!normalizeMtnCallbackHost(mtn.callbackHost)&&mtn.callbackHostRegistered===true;
 const paystackReady=!!paystack&&paystack.status==='active'&&paystack.provider==='PAYSTACK'&&paystack.workspaceId===workspaceId&&!!paystack.activeCredentialId&&!!normalizeMtnCallbackHost(paystack.callbackHost)&&paystack.webhookHostRegistered===true;
 const chosen=String(selection?.activeProvider||(!selection&&mtnReady?'MTN_COLLECTIONS':'DISABLED'));
 return{activeProvider:chosen==='MTN_COLLECTIONS'&&mtnReady?'MTN_COLLECTIONS':chosen==='PAYSTACK'&&paystackReady?'PAYSTACK':'DISABLED',mtnReady,paystackReady,mtn,paystack};
}

function paystackMobileMoneyCode(value:any):string {
 const code=String(value||'').toLowerCase();
 return ['mtn','atl','vod'].includes(code)?code:'';
}
function paystackLocalPhone(value:any):string {
 const normalized=normalizeGhanaPhone(value);
 return normalized?'0'+normalized.slice(3):'';
}
function validPaymentEmail(value:any):string {
 const email=String(value||'').trim().toLowerCase();
 return email.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)?email:'';
}
async function requestPaystackMobileMoneyCharge(input:{workspaceId:string;credentialId:string;merchantAccountId:string;email:string;phone:string;network:string;amount:number;reference:string;channel:'ONLINE_ORDER'|'POS';entityId:string;customer:string}) {
 const merchant=await loadWorkspacePaystackCredentials(input.workspaceId,input.credentialId);
 if(!merchant||merchant.merchantAccountId!==input.merchantAccountId)return{ok:false,unknown:false,httpStatus:503,payload:null,data:null,error:'Original workspace Paystack credentials are unavailable.'};
 const response=await fetch('https://api.paystack.co/charge',{method:'POST',headers:{Authorization:'Bearer '+merchant.credentials.secretKey,'Content-Type':'application/json'},body:JSON.stringify({email:input.email,amount:String(input.amount),currency:'GHS',reference:input.reference,mobile_money:{phone:input.phone,provider:input.network},metadata:{shopflowWorkspaceId:input.workspaceId,shopflowChannel:input.channel,shopflowOrderId:input.channel==='ONLINE_ORDER'?input.entityId:undefined,shopflowPaymentAttemptId:input.channel==='POS'?input.entityId:undefined,customer_name:input.customer}})});
 const payload=obj<any>(await response.json().catch(()=>({}))),data=obj<any>(payload.data);
 const ok=response.ok&&payload.status===true&&String(data.reference||'')===input.reference&&!!String(data.status||'');
 return{ok,unknown:!ok&&(response.status>=500||response.status===409||response.status===408),httpStatus:response.status,payload,data,error:String(payload.message||'Paystack did not return a conclusive Mobile Money charge response.')};
}

async function submitPaystackMobileMoneyOtp(input:{workspaceId:string;credentialId:string;merchantAccountId:string;reference:string;otp:string}){
 const merchant=await loadWorkspacePaystackCredentials(input.workspaceId,input.credentialId);
 if(!merchant||merchant.merchantAccountId!==input.merchantAccountId)return{ok:false,httpStatus:503,data:null,error:'Original workspace Paystack credentials are unavailable.'};
 const response=await fetch('https://api.paystack.co/charge/submit_otp',{method:'POST',headers:{Authorization:'Bearer '+merchant.credentials.secretKey,'Content-Type':'application/json'},body:JSON.stringify({otp:input.otp,reference:input.reference})});
 const payload=obj<any>(await response.json().catch(()=>({}))),data=obj<any>(payload.data),returnedReference=String(data.reference||input.reference);
 return{ok:response.ok&&payload.status===true&&returnedReference===input.reference,httpStatus:response.status,data,payload,error:String(payload.message||'Paystack could not accept the authorization code.')};
}

async function finalizePaidPosSale(attempt:any,providerReference:string,financialTransactionId:string) {
 const ownerId=String(attempt.ownerId),requestId=String(attempt.requestId),attemptId=String(attempt.id);
 if(attempt.status==='Paid'){const [receipt]=await db.get<any>('receipts',['receipt_'+requestId],{consistent:true});return res(200,{attemptId,status:'Paid',receiptNumber:receipt?.receiptNumber||null,receipt:receipt||null,replayed:true});}
 const saleId='sale_'+requestId,receiptId='receipt_'+requestId;
 const [existingSale]=await db.get<any>('sales',[saleId],{consistent:true});
 if(existingSale&&existingSale.ownerId===ownerId){const [existingReceipt]=await db.get<any>('receipts',[receiptId],{consistent:true});await setRecord('payment_records',attemptId,{...attempt,status:'Paid',paymentStatus:'Paid',financialTransactionId,providerReference,receiptNumber:existingReceipt?.receiptNumber||existingSale.number,paidAt:attempt.paidAt||new Date().toISOString()});return res(200,{attemptId,status:'Paid',receiptNumber:existingReceipt?.receiptNumber||existingSale.number,receipt:existingReceipt,replayed:true});}
 const products:any[]=[];
 for(const item of attempt.items||[]){const [product]=await db.get<Product>('products',[String(item.productId)]);if(!product||product.ownerId!==ownerId||!Number.isInteger(Number(item.qty))||product.stock<Number(item.qty))return bad('Payment was confirmed but inventory requires staff reconciliation. No sale or stock deduction was committed. Keep payment reference '+String(attempt.paystackReference||attempt.mtnReference||attemptId)+'.',409);products.push({...product,id:String(item.productId),qty:Number(item.qty)});}
 const now=new Date().toISOString(),number=docNo('RCPT'),identity=await getShopIdentity(ownerId);
 const lines=(attempt.items||[]).map((item:any)=>({productId:String(item.productId),name:String(item.name||''),qty:Number(item.qty),price:Number(item.price),lineTotal:Math.round(Number(item.price)*Number(item.qty)*100)/100}));
 const total=Math.round(lines.reduce((sum:number,item:any)=>sum+item.lineTotal,0)*100)/100;
 if(Math.round(total*100)!==Number(attempt.providerAmount||Math.round(total*100)))return bad('The verified payment amount no longer matches this POS sale. No stock was deducted.',409);
 const sale={id:saleId,number,requestId,cartSignature:attempt.cartSignature||'',items:lines,total,payment:'Mobile Money',customer:attempt.customer,customerPhone:attempt.phone,createdAt:now,ownerId,agentName:attempt.cashierName||'POS cashier',paymentProvider:attempt.paymentProvider,providerReference,financialTransactionId:String(financialTransactionId||''),paymentNetwork:attempt.paymentNetwork,channel:'POS'};
 const receipt={id:receiptId,ownerId,saleId,receiptNumber:number,number,storeName:identity.shopName,tagline:identity.tagline,city:identity.city,customer:attempt.customer,paymentMethod:'Mobile Money · '+String(attempt.paymentNetworkLabel||attempt.paymentNetwork||''),paymentStatus:'Received',items:lines.map((item:any)=>({productId:item.productId,name:item.name,qty:item.qty,unitPrice:item.price,lineTotal:item.lineTotal})),subtotal:total,discount:0,tax:0,total,currency:'GHS',cashierName:attempt.cashierName||'POS cashier',issuedAt:now,createdAt:now,channel:'POS',paymentProvider:attempt.paymentProvider,providerReference,financialTransactionId:String(financialTransactionId||'')};
 const operations:any[]=[db.tx.add('sales',[sale]),db.tx.add('receipts',[receipt]),db.tx.update('payment_records',[{id:attemptId,record:{...attempt,status:'Paid',paymentStatus:'Paid',providerReference,financialTransactionId:String(financialTransactionId||''),receiptNumber:number,paidAt:now,updatedAt:now},if:{status:attempt.status}}])];
 for(let i=0;i<products.length;i++){const p=products[i];operations.push(db.tx.update('products',[{id:p.id,record:{...p,stock:p.stock-p.qty,updatedAt:now},if:{stock:p.stock}}]));operations.push(db.tx.add('stock_moves',[{id:'pospay_move_'+requestId+'_'+i,productId:p.id,productName:p.name,type:'OUT',qty:p.qty,reason:'Verified Mobile Money POS sale '+number,actorName:attempt.cashierName||'POS cashier',ownerId,createdAt:now}]));}
 try{await db.transact(operations);}catch{const [recovered]=await db.get<any>('sales',[saleId],{consistent:true});if(!recovered||recovered.ownerId!==ownerId)return bad('Payment was verified but the POS sale could not be committed. Contact the Managing Director with payment reference '+providerReference+'.',409);const [savedReceipt]=await db.get<any>('receipts',[receiptId],{consistent:true});return res(200,{attemptId,status:'Paid',receiptNumber:savedReceipt?.receiptNumber||recovered.number,receipt:savedReceipt,replayed:true});}
 try{await create('audit_logs',{ownerId,actorId:attempt.cashierId||'pos-payment',actorName:attempt.cashierName||'POS cashier',action:'POS_MOBILE_MONEY_SALE_PAID',entity:'sales',recordId:saleId,receiptNumber:number,details:{paymentProvider:attempt.paymentProvider,providerReference,financialTransactionId},createdAt:now});}catch{}
 try{await publishShopEvent({ownerId,eventId:'pos_paid_'+attemptId,eventType:'POS_PAYMENT_RECEIVED',title:'POS payment received',body:'A Mobile Money POS payment of GHS '+total.toFixed(2)+' was verified.',phone:attempt.phone,consent:attempt.smsOptIn===true,sms:'Payment received: GHS '+total.toFixed(2)+' for your purchase. Thank you.'});}catch{}
 return res(200,{attemptId,status:'Paid',paymentStatus:'Paid',receiptNumber:number,receipt,total});
}
async function reconcilePaystackPosAttempt(attempt:any) {
 const attemptId=String(attempt.id),ownerId=String(attempt.ownerId);
 if(attempt.status==='Paid')return await finalizePaidPosSale(attempt,attempt.paystackReference,attempt.financialTransactionId||'');
 const merchant=await loadWorkspacePaystackCredentials(ownerId,String(attempt.paystackCredentialId||''));
 if(!merchant||merchant.merchantAccountId!==attempt.paystackMerchantAccountId||attempt.paymentProvider!=='PAYSTACK'||attempt.paymentEnvironment!=='production'||!attempt.paystackReference)return bad('The original workspace Paystack credentials for this POS payment are unavailable. No other merchant credentials will be used.',503);
 try{
  const response=await fetch('https://api.paystack.co/transaction/verify/'+encodeURIComponent(attempt.paystackReference),{headers:{Authorization:'Bearer '+merchant.credentials.secretKey}});
  if(response.status===404){await setRecord('payment_records',attemptId,{...attempt,status:'Failed',failureReason:'Paystack has no transaction for the original POS reference.',updatedAt:new Date().toISOString()});return res(200,{attemptId,status:'Failed',message:'Paystack has no transaction for this reference. No sale or stock deduction was created.'});}
  if(!response.ok)return bad('Paystack POS payment verification is unavailable. Keep this payment attempt and retry; do not initiate another charge.',502);
  const payload=obj<any>(await response.json()),result=obj<any>(payload.data);
  if(payload.status!==true||String(result.reference||'')!==String(attempt.paystackReference))return bad('Paystack verification did not match the original POS payment reference.',409);
  if(String(result.currency||'').toUpperCase()!=='GHS'||Math.round(Number(result.amount))!==Number(attempt.providerAmount))return bad('Verified Paystack amount or currency does not match this POS sale. No stock was deducted.',409);
  const status=String(result.status||'').toLowerCase(),now=new Date().toISOString();
  if(status==='success')return await finalizePaidPosSale(attempt,attempt.paystackReference,String(result.id||''));
  if(['failed','abandoned','reversed','expired'].includes(status)){await setRecord('payment_records',attemptId,{...attempt,status:'Failed',paystackChargeStatus:status,failureReason:String(result.gateway_response||result.message||status).slice(0,240),updatedAt:now});return res(200,{attemptId,status:'Failed',message:'Paystack did not complete this payment. No sale or stock deduction was created.'});}
  const updated={...attempt,status:'Pending',paystackChargeStatus:status||attempt.paystackChargeStatus,paystackDisplayText:attempt.paystackDisplayText||'',lastStatusCheckedAt:now,updatedAt:now};
  await setRecord('payment_records',attemptId,updated);
  return res(200,{attemptId,status:'Pending',providerStatus:updated.paystackChargeStatus,authorizationInstructions:updated.paystackDisplayText,message:'Payment is still awaiting authorization. Follow the instructions displayed for this transaction.'});
 }catch(error){console.error('PAYSTACK_POS_VERIFY_FAILURE '+JSON.stringify({attemptId,reference:attempt.paystackReference}));return bad('Paystack POS payment verification is temporarily unavailable. Retry shortly.',502);}
}

async function finalizePaidOnlineOrder(order:any,providerReference:string,financialTransactionId:string,paymentLabel:string){
 const ownerId=String(order.ownerId),orderId=String(order.id);
 if(order.status==='Paid')return res(200,{orderId,status:'Paid',total:order.total,receiptNumber:order.receiptNumber||null,replayed:true});
 const currentProducts:Product[]=[];
 for(const item of order.items||[]){
  const p=(await db.get<Product>('products',[item.productId]))[0];
  if(!p||p.ownerId!==ownerId||p.stock<item.qty)return bad('Payment succeeded but inventory needs staff reconciliation. Contact the shop and keep order reference '+orderId+'.',409);
  currentProducts.push(p);
 }
 const now=new Date().toISOString(),receipt=docNo('WEB'),saleId='websale_'+orderId,receiptId='receipt_'+saleId,shopIdentity=await getShopIdentity(ownerId),ops:any[]=[];
 for(let i=0;i<(order.items||[]).length;i++){
  const item=order.items[i],p=currentProducts[i];
  ops.push(db.tx.update('products',[{id:item.productId,record:{...p,stock:p.stock-item.qty,updatedAt:now},if:{stock:p.stock}}]));
  ops.push(db.tx.add('stock_moves',[{id:'webmove_'+orderId+'_'+i,productId:item.productId,productName:item.name,type:'OUT',qty:item.qty,reason:'Paid online order '+receipt,actorName:'Online checkout',ownerId,createdAt:now}]));
 }
 ops.push(db.tx.add('sales',[{id:saleId,number:receipt,requestId:order.requestId,items:order.items,total:order.total,payment:paymentLabel,customer:order.customer,customerPhone:order.phone,createdAt:now,ownerId,agentName:'Online customer',channel:'Online',paymentProvider:order.paymentProvider,providerReference,financialTransactionId:String(financialTransactionId||'')}]));
 const receiptRecord={id:receiptId,ownerId,saleId,receiptNumber:receipt,number:receipt,storeName:shopIdentity.shopName,tagline:shopIdentity.tagline,city:shopIdentity.city,customer:order.customer,paymentMethod:paymentLabel,paymentStatus:'Received',items:(order.items||[]).map((item:any)=>({productId:item.productId,name:item.name,qty:item.qty,unitPrice:item.price,lineTotal:Math.round(Number(item.price||0)*Number(item.qty||0)*100)/100})),subtotal:Number(order.subtotal??order.total),discount:Number(order.discount||0),tax:0,total:order.total,currency:'GHS',cashierName:'Online checkout',issuedAt:now,createdAt:now,channel:'Online',paymentProvider:order.paymentProvider,providerReference,financialTransactionId:String(financialTransactionId||'')};
 ops.push(db.tx.add('receipts',[receiptRecord]));
 ops.push(db.tx.update('web_orders',[{id:orderId,record:{...order,status:'Paid',paymentStatus:'Paid',receiptNumber:receipt,financialTransactionId:String(financialTransactionId||''),providerReference,paidAt:now,fulfillmentStatus:'Processing',fulfillmentTimeline:[{status:'Processing',at:now,actorName:'ShopFlow',note:'Payment confirmed. The order is awaiting seller processing.'}]},if:{status:order.status}}]));
 try{await db.transact(ops)}catch{
  const[recovered]=await db.get<any>('web_orders',[orderId],{consistent:true});
  if(recovered?.status!=='Paid')return bad('The payment provider confirmed payment, but the order could not be finalized automatically. Contact the shop with order reference '+orderId+'.',409);
  return res(200,{orderId,status:'Paid',total:recovered.total,receiptNumber:recovered.receiptNumber,replayed:true});
 }
 try{
  const customers=await owned<Customer>('customers',ownerId),existing=customers.find(c=>c.name.toLowerCase()===String(order.customer||'').toLowerCase());
  if(existing)await setRecord('customers',existing.id!,{...existing,visits:existing.visits+1,lifetimeValue:(existing.lifetimeValue||0)+order.total});
  else await create('customers',{name:order.customer,phone:order.phone,visits:1,lifetimeValue:order.total,ownerId});
  await create('audit_logs',{ownerId,actorId:'online-customer',actorName:order.customer,action:'ONLINE_ORDER_PAID',entity:'web_orders',recordId:orderId,receiptNumber:receipt,paymentProvider:order.paymentProvider,providerReference,createdAt:now});
 }catch(error){console.error('ONLINE_PAYMENT_POST_COMMIT_HOUSEKEEPING_FAILED '+JSON.stringify({orderId,paymentProvider:order.paymentProvider}));}
 try{await publishShopEvent({ownerId,eventId:'online_paid_'+orderId,eventType:'ONLINE_ORDER_PAID',title:'Online order paid',body:'Order '+receipt+' has been paid and is ready for processing.',phone:order.phone,consent:order.smsOptIn===true,sms:'Payment confirmed for order '+receipt+'. Amount GHS '+Number(order.total).toFixed(2)+'. The shop is preparing your order.'});}catch{}
 return res(200,{orderId,status:'Paid',paymentStatus:'Paid',fulfillmentStatus:'Processing',total:order.total,receiptNumber:receipt});
}
async function verifyPaystackSignature(rawBody:string,signature:string,secretKey:string){
 if(!rawBody||!signature||!/^[a-f0-9]{128}$/i.test(signature))return false;
 const key=await crypto.subtle.importKey('raw',enc.encode(secretKey),{name:'HMAC',hash:'SHA-512'},false,['sign']);
 const digest=new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(rawBody)));
 const expected=Array.from(digest,b=>b.toString(16).padStart(2,'0')).join('');
 if(expected.length!==signature.length)return false;
 let mismatch=0;for(let i=0;i<expected.length;i++)mismatch|=expected.charCodeAt(i)^signature.toLowerCase().charCodeAt(i);
 return mismatch===0;
}

const TENANT_SHADOW_TABLES=['products','stock_moves','sales','receipts','customers','suppliers','purchases','expenses','invoices','web_orders','payment_records','audit_logs','change_requests','marketplace_settings'];
async function tenantShadowSchema(ownerId:string){
 const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(ownerId)));
 const hex=Array.from(digest,b=>b.toString(16).padStart(2,'0')).join('');
 return 'tenant_'+hex.slice(0,24);
}
async function openMigrationPool(){
 const names=await secrets.listSecretNames();
 if(!names.includes('DATABASE_URL'))throw new Error('postgres_connection_not_configured');
 const connectionString=await secrets.readSecret('DATABASE_URL');
 return new Pool({connectionString,connectionTimeoutMillis:5000,idleTimeoutMillis:1000,max:1,ssl:{rejectUnauthorized:true}});
}
async function ensureTenantShadowSchema(pool:Pool,ownerId:string,schema:string){
 await pool.query('CREATE SCHEMA IF NOT EXISTS shopflow_control');
 await pool.query("CREATE TABLE IF NOT EXISTS shopflow_control.workspace_migrations (workspace_id text PRIMARY KEY, schema_name text NOT NULL, state text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())");
 await pool.query("CREATE TABLE IF NOT EXISTS shopflow_control.workspace_migration_progress (workspace_id text NOT NULL, source_table text NOT NULL, next_token text, scanned_count bigint NOT NULL DEFAULT 0, copied_count bigint NOT NULL DEFAULT 0, skipped_count bigint NOT NULL DEFAULT 0, pages_completed bigint NOT NULL DEFAULT 0, complete boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(workspace_id,source_table), FOREIGN KEY(workspace_id) REFERENCES shopflow_control.workspace_migrations(workspace_id))");
 await pool.query('CREATE SCHEMA IF NOT EXISTS "'+schema+'"');
 await pool.query('CREATE TABLE IF NOT EXISTS "'+schema+'".records (entity text NOT NULL, record_id text NOT NULL, owner_id text NOT NULL, payload jsonb NOT NULL, source_hash text NOT NULL, migrated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(entity,record_id))');
 await pool.query('CREATE INDEX IF NOT EXISTS tenant_records_owner_entity_idx ON "'+schema+'".records(owner_id,entity)');
 await pool.query("INSERT INTO shopflow_control.workspace_migrations(workspace_id,schema_name,state) VALUES($1,$2,'shadow_copy_in_progress') ON CONFLICT(workspace_id) DO NOTHING",[ownerId,schema]);
 for(const table of TENANT_SHADOW_TABLES)await pool.query('INSERT INTO shopflow_control.workspace_migration_progress(workspace_id,source_table) VALUES($1,$2) ON CONFLICT(workspace_id,source_table) DO NOTHING',[ownerId,table]);
}
async function tenantShadowStatus(pool:Pool,ownerId:string){
 const exists=await pool.query("SELECT to_regclass('shopflow_control.workspace_migrations') AS relation");
 if(!exists.rows[0]?.relation)return{state:'not_started',tables:[],cutoverEligible:false};
 const migration=await pool.query('SELECT state,started_at,updated_at FROM shopflow_control.workspace_migrations WHERE workspace_id=$1',[ownerId]);
 if(!migration.rows.length)return{state:'not_started',tables:[],cutoverEligible:false};
 const progress=await pool.query('SELECT source_table,scanned_count,copied_count,skipped_count,pages_completed,complete,updated_at FROM shopflow_control.workspace_migration_progress WHERE workspace_id=$1 ORDER BY source_table',[ownerId]);
 return{state:migration.rows[0].state,startedAt:migration.rows[0].started_at,updatedAt:migration.rows[0].updated_at,tables:progress.rows.map((x:any)=>({sourceTable:x.source_table,scanned:Number(x.scanned_count),copied:Number(x.copied_count),skipped:Number(x.skipped_count),pagesCompleted:Number(x.pages_completed),complete:x.complete,updatedAt:x.updated_at})),cutoverEligible:false,notice:'This is a non-destructive shadow copy. Scanned, copied and skipped source records are tracked separately. AppDeploy remains authoritative until dual-write, reconciliation and a separately approved cutover are implemented.'};
}

function mtnSafeNote(value:string,max=160){
 return value.normalize('NFKD').replace(/[^A-Za-z0-9 ]/g,' ').replace(/\s+/g,' ').trim().slice(0,max)||'ShopFlow payment';
}
function normalizeMtnCallbackHost(value:any):string|null{
 const raw=String(value||'').trim().toLowerCase();if(!raw||raw.length>253||raw.includes('/')||raw.includes('\\')||/[:?#@\s]/.test(raw))return null;
 try{const parsed=new URL('https://'+raw),host=parsed.hostname.toLowerCase();if(host!==raw||parsed.port||parsed.pathname!=='/'||parsed.search||parsed.hash||!host.includes('.')||host.endsWith('.')||host==='localhost'||host.endsWith('.localhost')||host.endsWith('.local')||host.endsWith('.internal')||/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host))return null;if(!host.split('.').every(label=>label.length>0&&label.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)))return null;return host}catch{return null}
}
type FxRateSnapshot={rate:number;source:string;lastUpdatedAt:string;lastUpdatedUnix:number;nextUpdateUnix:number;fetchedAt:string};
let mtnFxMemory:FxRateSnapshot|null=null;
async function getMtnSandboxFxRate(force=false):Promise<FxRateSnapshot>{
 const now=Date.now();
 if(!force&&mtnFxMemory&&now<mtnFxMemory.nextUpdateUnix*1000)return mtnFxMemory;
 const cacheId='system_fx_GHS_EUR';
 const [stored]=await db.get<any>('marketplace_settings',[cacheId],{consistent:true});
 const storedRate=num(stored?.rate),storedUpdated=num(stored?.lastUpdatedUnix),storedNext=num(stored?.nextUpdateUnix);
 const storedValid=stored?.baseCurrency==='GHS'&&stored?.quoteCurrency==='EUR'&&Number.isFinite(storedRate)&&storedRate>0&&storedRate<1.5&&Number.isFinite(storedUpdated)&&storedUpdated>0&&now-storedUpdated*1000<=36*60*60*1000;
 if(!force&&storedValid&&Number.isFinite(storedNext)&&now<storedNext*1000){
  mtnFxMemory={rate:storedRate,source:'ExchangeRate-API Open Access',lastUpdatedAt:String(stored.lastUpdatedAt),lastUpdatedUnix:storedUpdated,nextUpdateUnix:storedNext,fetchedAt:String(stored.fetchedAt||'')};
  return mtnFxMemory;
 }
 let timer:any;
 try{
  const controller=new AbortController();timer=setTimeout(()=>controller.abort(),7000);
  const response=await fetch('https://open.er-api.com/v6/latest/GHS',{signal:controller.signal,headers:{'Accept':'application/json'}});
  if(!response.ok)throw new Error('fx_provider_http_'+response.status);
  const payload=obj<any>(await response.json());
  const rate=num(payload?.rates?.EUR),lastUpdatedUnix=num(payload?.time_last_update_unix),nextUpdateUnix=num(payload?.time_next_update_unix);
  if(payload?.result!=='success'||payload?.base_code!=='GHS'||!Number.isFinite(rate)||rate<=0||rate>=1.5||!Number.isFinite(lastUpdatedUnix)||!Number.isFinite(nextUpdateUnix)||lastUpdatedUnix>now/1000+300||now-lastUpdatedUnix*1000>36*60*60*1000||nextUpdateUnix<=lastUpdatedUnix)throw new Error('fx_provider_payload_invalid_or_stale');
  const snapshot:FxRateSnapshot={rate,source:'ExchangeRate-API Open Access',lastUpdatedAt:String(payload.time_last_update_utc||new Date(lastUpdatedUnix*1000).toISOString()),lastUpdatedUnix,nextUpdateUnix,fetchedAt:new Date().toISOString()};
  const record={id:cacheId,ownerId:'__system__',baseCurrency:'GHS',quoteCurrency:'EUR',...snapshot};
  if(stored)await setRecord('marketplace_settings',cacheId,record);
  else await db.tx.add('marketplace_settings',[record]);
  mtnFxMemory=snapshot;
  return snapshot;
 }catch(error){
  if(storedValid&&now-storedUpdated*1000<=36*60*60*1000){
   const fallback:FxRateSnapshot={rate:storedRate,source:'ExchangeRate-API Open Access (cached fallback)',lastUpdatedAt:String(stored.lastUpdatedAt),lastUpdatedUnix:storedUpdated,nextUpdateUnix:storedNext||storedUpdated+86400,fetchedAt:String(stored.fetchedAt||'')};
   mtnFxMemory=fallback;
   return fallback;
  }
  throw error;
 }finally{if(timer)clearTimeout(timer)}
}
async function mtnProviderError(response:Response){
 const raw=await response.clone().text().catch(()=> '');
 let body:any={};
 try{body=JSON.parse(raw)}catch{}
 const rawCode=body?.code??body?.errorCode??body?.statusCode??body?.error??body?.reason?.code;
 const rawMessage=body?.message??body?.error_description??body?.description??body?.reason?.message;
 const clean=(value:unknown,max:number)=>typeof value==='string'?value.replace(/\b(?:233|0)\d{9}\b/g,'[msisdn]').replace(/[^A-Za-z0-9 _.-]/g,' ').replace(/\s+/g,' ').trim().slice(0,max):undefined;
 const bodySummary=clean(raw,240);
 const code=clean(typeof rawCode==='string'?rawCode:JSON.stringify(rawCode||''),80);
 const message=clean(typeof rawMessage==='string'?rawMessage:JSON.stringify(rawMessage||''),160);
 const rejected=(response.status>=400&&response.status<500&&response.status!==409)||(response.status>=200&&response.status<300&&!!raw&&(!!rawCode||!!rawMessage||/request rejected|bad request|invalid_currency|invalid parameters|not allowed/i.test(raw)));
 return{httpStatus:response.status,code,message,bodySummary,contentType:response.headers.get('content-type')||'',correlationId:clean(response.headers.get('x-correlation-id')||response.headers.get('x-request-id')||'',100),rejected};
}

async function getVapidKeys(){const id='shopflow_vapid_keys_v1',ws='shopflow-platform',[old]=await db.get<any>('integration_secrets',[id],{consistent:true}),master=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY');if(old?.publicKey&&old?.ciphertext){const saved=obj<any>(JSON.parse(await decryptWorkspacePaymentCredentials(old,master,ws,id)));if(saved.privateKey)return{publicKey:old.publicKey,privateKey:saved.privateKey};}const keys=webpush.generateVAPIDKeys(),encKey=await encryptWorkspacePaymentCredentials(JSON.stringify({privateKey:keys.privateKey}),master,ws,id),r={id,workspaceId:ws,ownerId:'platform',recordType:'vapid_keys',publicKey:keys.publicKey,...encKey,createdAt:new Date().toISOString(),keyVersion:1};if(old)await setRecord('integration_secrets',id,r);else await db.tx.add('integration_secrets',[r]);return keys;}
async function hubtelSms(ownerId:string,phone:string,message:string,eventId:string){const msisdn=normalizeGhanaPhone(phone);if(!msisdn||!message||message.length>480)return false;const logId='sms_'+eventId,[old]=await db.get<any>('sms_logs',[logId],{consistent:true});if(old?.status==='accepted'||old?.status==='sending')return old.status==='accepted';const[ptr]=await db.get<any>('integration_secrets',['hubtel_sms_workspace_'+ownerId],{consistent:true});if(!ptr||ptr.status!=='active'||ptr.workspaceId!==ownerId||!ptr.activeCredentialId)return false;const cid=ptr.activeCredentialId,[cred]=await db.get<any>('integration_secrets',[cid],{consistent:true});if(!cred||cred.workspaceId!==ownerId||cred.provider!=='HUBTEL_SMS')return false;const master=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'),c=obj<any>(JSON.parse(await decryptWorkspacePaymentCredentials(cred,master,ownerId,cid))),now=new Date().toISOString(),log={id:logId,ownerId,provider:'HUBTEL_SMS',status:'sending',recipient:'+'+msisdn,createdAt:now,updatedAt:now};if(old)await setRecord('sms_logs',logId,log);else await db.tx.add('sms_logs',[log]);try{const r=await fetch('https://smsc.hubtel.com/v1/messages/send',{method:'POST',headers:{Authorization:'Basic '+btoa(c.clientId+':'+c.clientSecret),'Content-Type':'application/json'},body:JSON.stringify({from:c.senderId,to:'+'+msisdn,content:message})}),j=obj<any>(await r.json().catch(()=>({}))),d=obj<any>(j.data||j.Data),ok=r.ok&&(String(j.responseCode||j.Code||'')==='00'||!!(d.messageId||d.MessageId)||String(d.status||d.Status||'').toLowerCase()==='sent');await setRecord('sms_logs',logId,{...log,status:ok?'accepted':'failed',providerMessageId:String(d.messageId||d.MessageId||''),httpStatus:r.status,updatedAt:new Date().toISOString()});return ok;}catch{await setRecord('sms_logs',logId,{...log,status:'failed',updatedAt:new Date().toISOString()});return false;}}
async function publishShopEvent(e:{ownerId:string;eventId:string;eventType:string;title:string;body:string;phone?:string;consent?:boolean;sms?:string}){const now=new Date().toISOString(),[ev]=await db.get<any>('notification_events',[e.eventId],{consistent:true});if(!ev)await db.tx.add('notification_events',[{id:e.eventId,ownerId:e.ownerId,eventType:e.eventType,title:e.title,body:e.body,createdAt:now}]);try{const staff=(await owned<User>('users',e.ownerId)).filter(u=>u.active!==false&&u.id),subs=(await db.list<any>('push_subscriptions',{limit:500})).items.filter(x=>x.ownerId===e.ownerId);if(subs.length){const k=await getVapidKeys();webpush.setVapidDetails(SHOPFLOW_PUBLIC_ORIGIN+'/',k.publicKey,k.privateKey);}for(const u of staff){const nid=('notify_'+e.eventId+'_'+u.id).slice(0,180),[n]=await db.get<any>('notifications',[nid],{consistent:true});if(!n)await db.tx.add('notifications',[{id:nid,ownerId:e.ownerId,userId:u.id,title:e.title,body:e.body,eventId:e.eventId,eventType:e.eventType,readAt:null,createdAt:now}]);for(const sub of subs.filter(x=>x.userId===u.id)){try{await webpush.sendNotification({endpoint:sub.endpoint,keys:sub.keys},JSON.stringify({title:e.title,body:e.body,url:'/',eventId:e.eventId}),{TTL:300});}catch(err:any){if([404,410].includes(Number(err?.statusCode)))await db.delete('push_subscriptions',[sub.id]);}}}}catch{console.error('STAFF_PUSH_DISPATCH_FAILED '+e.eventId);}if(e.phone&&e.consent===true&&e.sms)try{await hubtelSms(e.ownerId,e.phone,e.sms,e.eventId);}catch{console.error('CUSTOMER_SMS_DISPATCH_FAILED '+e.eventId);}}
async function publishPlatformRegistrationAlert(application:any){
 const eventId='shop_registration_submitted_'+application.id,now=new Date().toISOString(),title='New shop registration application',body=application.shopName+' submitted by '+application.ownerName+' is awaiting Super Admin review.';
 try{
  const admins=(await all<User>('users')).filter(user=>user.role==='Super Admin'&&user.active!==false);
  const [existing]=await db.get<any>('notification_events',[eventId],{consistent:true});
  if(!existing)await create('notification_events',{id:eventId,ownerId:'shopflow_platform',eventType:'SHOP_REGISTRATION_SUBMITTED',title,body,createdAt:now});
  const subscriptions=(await db.list<any>('push_subscriptions',{limit:500})).items.filter(sub=>admins.some(admin=>admin.id===sub.userId));
  if(subscriptions.length){const keys=await getVapidKeys();webpush.setVapidDetails(SHOPFLOW_PUBLIC_ORIGIN+'/',keys.publicKey,keys.privateKey);}
  for(const admin of admins){
   const notificationId=('notify_'+eventId+'_'+admin.id).slice(0,180),[existingNotification]=await db.get<any>('notifications',[notificationId],{consistent:true});
   if(!existingNotification)await create('notifications',{id:notificationId,ownerId:'shopflow_platform',userId:admin.id,title,body,eventId,eventType:'SHOP_REGISTRATION_SUBMITTED',readAt:null,createdAt:now});
   for(const sub of subscriptions.filter(item=>item.userId===admin.id)){
    try{await webpush.sendNotification({endpoint:sub.endpoint,keys:sub.keys},JSON.stringify({title,body,url:'/?platformAlert='+encodeURIComponent(application.id),eventId}),{TTL:300});}
    catch(error:any){if([404,410].includes(Number(error?.statusCode)))await db.delete('push_subscriptions',[sub.id]);else console.error('PLATFORM_REGISTRATION_PUSH_FAILED '+eventId);}
   }
  }
 }catch{console.error('PLATFORM_REGISTRATION_ALERT_FAILED '+eventId);}
}
async function getCheckoutPromotion(ownerId:string,code:string){if(!code)return null;const p=(await owned<any>('promotions',ownerId)).find(x=>String(x.code||'').toUpperCase()===code&&x.active===true),now=Date.now();if(!p)return{error:'Promotion code is invalid or inactive.'};if(p.startsAt&&Date.parse(p.startsAt)>now||p.endsAt&&Date.parse(p.endsAt)<now)return{error:'Promotion is outside its valid date range.'};return p;}


const routeHandler=router({
'GET /api/_healthcheck':[async()=>json({status:'ok',service:'shopflow'})],
'GET /api/admin/postgres/health':[async ctx=>{
 const s=await session(ctx,false);
 if(!s)return bad('Sign in to continue.',401);
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can verify database infrastructure.',403);
 const names=await secrets.listSecretNames();
 if(!names.includes('DATABASE_URL'))return bad('PostgreSQL connection is not configured.',503);
 let pool:Pool|undefined;
 try{
  const connectionString=await secrets.readSecret('DATABASE_URL');
  pool=new Pool({connectionString,connectionTimeoutMillis:5000,idleTimeoutMillis:1000,max:1,ssl:{rejectUnauthorized:true}});
  await pool.query('SELECT 1 AS connected');
  return res(200,{ok:true,provider:'PostgreSQL',connection:'verified',migration:'not_started',message:'PostgreSQL is reachable. No application records have been copied or changed.'});
 }catch{
  return bad('PostgreSQL connection could not be verified. Check the connection URL, TLS certificate, database availability and network allowlist.',503);
 }finally{
  if(pool)await pool.end().catch(()=>undefined);
 }
}],

'GET /api/admin/postgres/migration/status':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can view tenant data migration status.',403);
 let pool:Pool|undefined;
 try{pool=await openMigrationPool();return res(200,await tenantShadowStatus(pool,s.user.ownerId||s.userId));}
 catch{return bad('PostgreSQL migration status could not be read. Verify the database connection and permissions.',503);}
 finally{if(pool)await pool.end().catch(()=>undefined);}
}],
'POST /api/admin/postgres/migration/prepare':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can prepare tenant data storage.',403);
 const ownerId=s.user.ownerId||s.userId,schema=await tenantShadowSchema(ownerId);let pool:Pool|undefined;
 try{
  pool=await openMigrationPool();await ensureTenantShadowSchema(pool,ownerId,schema);
  const status=await tenantShadowStatus(pool,ownerId);
  return res(200,{...status,schemaPrepared:true,message:'Workspace-specific PostgreSQL schema and resumable migration checkpoints are ready. Existing AppDeploy records were not modified.'});
 }catch(error:any){
  console.error('TENANT_SHADOW_PREPARE_FAILED '+String(error?.code||'postgres_error'));
  return bad('PostgreSQL tenant storage could not be prepared. No source records were changed; verify DATABASE_URL permissions and retry after resolving the database error.',503);
 }finally{if(pool)await pool.end().catch(()=>undefined);}
}],
'POST /api/admin/postgres/migration/step':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can run tenant data migration.',403);
 const ownerId=s.user.ownerId||s.userId;let pool:Pool|undefined,client:any;
 try{
  pool=await openMigrationPool();
  const migration=await pool.query('SELECT schema_name,state FROM shopflow_control.workspace_migrations WHERE workspace_id=$1',[ownerId]);
  if(!migration.rows.length)return bad('Prepare the workspace PostgreSQL storage before copying records.',409);
  const schema=String(migration.rows[0].schema_name||'');
  if(!/^tenant_[a-f0-9]{24}$/.test(schema))return bad('The workspace migration schema identifier is invalid. Contact support.',500);
  client=await pool.connect();await client.query('BEGIN');
  const progressResult=await client.query('SELECT source_table,next_token,complete FROM shopflow_control.workspace_migration_progress WHERE workspace_id=$1 AND complete=false ORDER BY array_position($2::text[],source_table) LIMIT 1 FOR UPDATE',[ownerId,TENANT_SHADOW_TABLES]);
  if(!progressResult.rows.length){
   await client.query("UPDATE shopflow_control.workspace_migrations SET state='shadow_copy_complete_requires_dual_write_and_reconciliation',updated_at=now() WHERE workspace_id=$1",[ownerId]);
   await client.query('COMMIT');
   return res(200,{...(await tenantShadowStatus(pool,ownerId)),message:'All configured source tables have been scanned. This shadow copy is not cutover-ready; dual-write and final reconciliation remain mandatory.'});
  }
  const progress=progressResult.rows[0],sourceTable=String(progress.source_table);
  if(!TENANT_SHADOW_TABLES.includes(sourceTable))throw new Error('migration_source_table_not_allowed');
  const page=await db.list<Record<string,any>>(sourceTable,{limit:3,...(progress.next_token?{nextToken:progress.next_token}:{})});
  const matching=page.items.filter((item:any)=>item.ownerId===ownerId&&typeof item.id==='string');
  if(matching.length){
   const payload=matching.map((item:any)=>({record_id:item.id,payload:item}));
   const serialized=JSON.stringify(payload);
   await client.query('INSERT INTO "'+schema+'".records(entity,record_id,owner_id,payload,source_hash,migrated_at) SELECT $1,x.record_id,$2,x.payload,md5(x.payload::text),now() FROM jsonb_to_recordset($3::jsonb) AS x(record_id text,payload jsonb) ON CONFLICT(entity,record_id) DO UPDATE SET owner_id=EXCLUDED.owner_id,payload=EXCLUDED.payload,source_hash=EXCLUDED.source_hash,migrated_at=now()',[sourceTable,ownerId,serialized]);
  }
  const complete=!page.nextToken;
  const scannedCount=page.items.length,copiedCount=matching.length,skippedCount=scannedCount-copiedCount;
  await client.query('UPDATE shopflow_control.workspace_migration_progress SET next_token=$3,scanned_count=scanned_count+$4,copied_count=copied_count+$5,skipped_count=skipped_count+$6,pages_completed=pages_completed+1,complete=$7,updated_at=now() WHERE workspace_id=$1 AND source_table=$2',[ownerId,sourceTable,page.nextToken||null,scannedCount,copiedCount,skippedCount,complete]);
  const remaining=await client.query('SELECT count(*)::int AS count FROM shopflow_control.workspace_migration_progress WHERE workspace_id=$1 AND complete=false',[ownerId]);
  const state=remaining.rows[0].count===0?'shadow_copy_complete_requires_dual_write_and_reconciliation':'shadow_copy_in_progress';
  await client.query('UPDATE shopflow_control.workspace_migrations SET state=$2,updated_at=now() WHERE workspace_id=$1',[ownerId,state]);
  await client.query('COMMIT');
  return res(200,{...(await tenantShadowStatus(pool,ownerId)),lastBatch:{sourceTable,scanned:scannedCount,copied:copiedCount,skipped:skippedCount},message:complete?'Source table '+sourceTable+' has been fully scanned.':'Processed the next bounded page from '+sourceTable+'. Run another batch to continue.'});
 }catch(error:any){
  if(client)await client.query('ROLLBACK').catch(()=>undefined);
  const code=String(error?.code||'');
  console.error('TENANT_SHADOW_STEP_FAILED '+code);
  if(code==='AppDatabaseQuotaExceeded'||code==='AppDatabaseGatewayUnavailable'||code==='AppDatabaseReadIncomplete')return bad('The source database could not provide a complete page. No checkpoint was advanced; resolve the database condition before retrying.',503);
  return bad('The next migration batch could not be committed. Its PostgreSQL checkpoint was rolled back; retry after checking the database connection.',503);
 }finally{if(client)client.release();if(pool)await pool.end().catch(()=>undefined);}
}],
'POST /api/admin/database-reset':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can reset the business database.',403);
 const b=obj<{confirmation?:string}>(ctx.body);
 if(b.confirmation!=='RESET SHOPFLOW DATABASE')return bad('The reset confirmation phrase does not match.',400);
 const ownerId=s.user.ownerId||s.userId;
 const tables=['users','sessions','password_resets','products','stock_moves','sales','receipts','customers','suppliers','purchases','expenses','invoices','web_orders','payment_records','audit_logs','change_requests','marketplace_settings'];
 const pages=await Promise.all(tables.map(async table=>({table,page:await db.list<Record<string,any>>(table,{limit:500})})));
 const tenantUserIds=new Set((pages.find(x=>x.table==='users')?.page.items||[]).filter(item=>item.ownerId===ownerId).map(item=>item.id));
 const scopedPages=pages.map(x=>({table:x.table,items:x.table==='sessions'?x.page.items.filter(item=>tenantUserIds.has(item.userId)):x.page.items.filter(item=>item.ownerId===ownerId),nextToken:x.page.nextToken}));
 const overflow=scopedPages.find(x=>x.nextToken);
 if(overflow)return bad('Reset stopped without deleting anything: table '+overflow.table+' exceeds the safe single-page limit. Use a paginated tenant reset workflow.',409);
 const populated=scopedPages.filter(x=>x.items.length>0);
 if(populated.length){
  const operations=populated.map(x=>db.tx.delete(x.table,x.items.map(item=>item.id)));
  const outcomes=await db.transact(operations);
  if(outcomes.some(result=>result.some(ok=>!ok)))return bad('The tenant database reset did not complete cleanly. Do not create new records; contact support for reconciliation.',500);
 }
 const deleted=Object.fromEntries(scopedPages.map(x=>[x.table,x.items.length]));
 return res(200,{ok:true,deleted,preserved:['database schemas','integration_secrets table and records','workspace payment encryption key','independent MTN Collections and Paystack workspace credentials'],message:'Application records were permanently deleted. Database schemas and independent MTN / Paystack workspace payment configurations were preserved.'},{'set-cookie':setCookie('',0)});
}],
'POST /api/storage/product-image':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const s=await session(ctx),denied=guard(ctx,s,'products');if(denied)return denied;
 const b=obj<{contentType?:string;data?:string}>(ctx.body),contentType=String(b.contentType||''),data=String(b.data||'');
 const extensions:Record<string,string>={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/avif':'avif','image/gif':'gif'};
 if(!extensions[contentType]||!data||data.length>7_000_000||!/^[A-Za-z0-9+/]+={0,2}$/.test(data))return bad('Upload a JPEG, PNG, WebP, AVIF or GIF image no larger than 5 MB.',400);
 const ownerId=s.user.ownerId||s.userId,path='shops/'+ownerId+'/products/'+token(18)+'.'+extensions[contentType];
 const[ok]=await storage.write([{path,content:data,contentType}]);
 if(!ok)return bad('Product image could not be stored. Try again.',502);
 const[entry]=await storage.url([path]);
 return res(201,{storagePath:'storage://'+path,url:entry?.url||'',contentType});
}],
'POST /api/storage/profile-image':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);const s=await session(ctx);if(!s)return bad('Session or CSRF token is invalid.',403);
 const b=obj<{contentType?:string;data?:string}>(ctx.body),contentType=String(b.contentType||''),data=String(b.data||''),extensions:Record<string,string>={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/avif':'avif','image/gif':'gif'};
 if(!extensions[contentType]||!data||data.length>7_000_000||!/^[A-Za-z0-9+/]+={0,2}$/.test(data))return bad('Upload a JPEG, PNG, WebP, AVIF or GIF profile picture no larger than 5 MB.',400);
 const ownerId=s.user.ownerId||s.userId;if(!/^[A-Za-z0-9_-]{1,120}$/.test(ownerId)||!/^[A-Za-z0-9_-]{1,120}$/.test(s.userId))return bad('Account storage identity is invalid.',400);
 const path='shops/'+ownerId+'/profiles/'+s.userId+'/'+token(18)+'.'+extensions[contentType];const[ok]=await storage.write([{path,content:data,contentType}]);if(!ok)return bad('Profile picture could not be stored. Try again.',502);const[entry]=await storage.url([path]);return res(201,{storagePath:'storage://'+path,url:entry?.url||'',contentType});
}],
'GET /api/storefront/catalog':[async()=>{
 const configs=await db.list<any>('marketplace_settings',{limit:500});
 const participating=configs.items.filter(x=>x.marketplaceEnabled===true&&x.ownerId);
 const items:any[]=[];
 for(const cfg of participating){
  const payment=await getWorkspaceActivePaymentProvider(cfg.ownerId);
  const products=await owned<Product>('products',cfg.ownerId);
  for(const p of products){
   if(p.stock>0&&Number.isFinite(Number(p.price))&&p.price>0)items.push({id:p.id,ownerId:cfg.ownerId,name:p.name,category:p.category||'Other',price:p.price,stock:p.stock,sku:p.sku||'',imageUrl:await resolveProductImage(p.imageUrl||'',cfg.ownerId),imageGallery:await Promise.all((Array.isArray(p.imageGallery)?p.imageGallery:[]).map(async(entry:any)=>typeof entry==='string'?await resolveProductImage(entry,cfg.ownerId):({view:String(entry?.view||'Additional view'),url:await resolveProductImage(String(entry?.url||''),cfg.ownerId)}))),brand:p.brand||'',model:p.model||'',condition:p.condition||'',color:p.color||'',size:p.size||'',material:p.material||'',warranty:p.warranty||'',features:p.features||'',specifications:p.specifications||'',description:p.description||'',storeName:resolveShopIdentity(cfg,cfg.ownerId).shopName,city:cfg.city||'',paymentProvider:payment.activeProvider});
  }
 }
 items.sort((a,b)=>String(a.name).localeCompare(String(b.name)));
 return res(200,{items,shops:await Promise.all(participating.map(async x=>({id:x.ownerId,...resolveShopIdentity(x,x.ownerId),paymentProvider:(await getWorkspaceActivePaymentProvider(x.ownerId)).activeProvider}))),total:items.length,storeLimit:500});
}],
'POST /api/storefront/order-lookup':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const rawBody=ctx.body;
 let parsedBody:any=rawBody;
 if(typeof rawBody==='string'){try{parsedBody=JSON.parse(rawBody)}catch{parsedBody={}}}
 const b=obj<any>(parsedBody);
 const reference=String(b.orderId||b.reference||b.orderReference||b.orderNumber||b.receiptNumber||'').trim().replace(/\s+/g,'');
 const phone=normalizeGhanaPhone(b.phone||b.mobileNumber||b.checkoutPhone||b.mobile||b.msisdn);
 if(!reference||reference.length>120||!/^[A-Za-z0-9][A-Za-z0-9_-]{5,119}$/.test(reference))return bad('Enter the order ID or receipt reference shown after checkout.',400);
 if(!phone)return bad('Enter a valid Ghana mobile number, for example 0241234567 or +233241234567.',400);
 let order:any=null;
 if(reference.startsWith('weborder_')){
  const [byId]=await db.get<any>('web_orders',[reference],{consistent:true});
  order=byId||null;
 }
 if(!order){
  const page=await db.list<any>('web_orders',{limit:500});
  order=page.items.find((item:any)=>String(item.id||'')===reference||String(item.receiptNumber||'')===reference)||null;
 }
 if(!order||normalizeGhanaPhone(order.phone)!==phone)return bad('Order not found. Check the reference and checkout mobile number.',404);
 const orderId=String(order.id||reference);
 const identity=await getShopIdentity(order.ownerId);
 return res(200,{orderId,storeId:order.ownerId,storeName:identity.shopName,customer:order.customer,total:order.total,currency:order.currency||'GHS',paymentStatus:order.status==='Paid'?'Paid':order.status,status:order.status,paymentProvider:order.paymentProvider||'MTN_COLLECTIONS',payment:order.payment||'MTN Mobile Money',providerStatus:order.paystackChargeStatus||'',authorizationInstructions:order.paystackDisplayText||'',receiptNumber:order.receiptNumber||null,paidAt:order.paidAt||null,fulfillmentStatus:order.fulfillmentStatus||(order.status==='Paid'?'Processing':null),fulfillmentTimeline:Array.isArray(order.fulfillmentTimeline)?order.fulfillmentTimeline:[],trackingNumber:order.trackingNumber||null,courierName:order.courierName||null,dispatchReference:order.dispatchReference||null,deliveryRecipient:order.deliveryRecipient||order.customer||null,deliveryPhone:order.deliveryPhone||order.phone||null,destinationAddress:order.destinationAddress||null,destinationCity:order.destinationCity||null,destinationRegion:order.destinationRegion||null,destinationPostalCode:order.destinationPostalCode||null,destinationLandmark:order.destinationLandmark||null,deliveryInstructions:order.deliveryInstructions||null,shippingMethod:order.shippingMethod||null,estimatedDelivery:order.estimatedDelivery||null,returnStatus:order.returnStatus||null,returnReason:order.returnReason||null,items:(order.items||[]).map((item:any)=>({name:item.name,qty:item.qty,price:item.price}))});
}],
'POST /api/storefront/order-action':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<any>(ctx.body),orderId=String(b.orderId||'').trim(),phone=normalizeGhanaPhone(b.phone),action=String(b.action||''),reason=String(b.reason||'').trim();
 if(!/^weborder_[A-Za-z0-9_-]{16,80}$/.test(orderId)||!phone||action!=='return'||reason.length<10||reason.length>500)return bad('Provide a valid order reference, checkout mobile number and return reason (10–500 characters).',400);
 const [order]=await db.get<any>('web_orders',[orderId],{consistent:true});
 if(!order||normalizeGhanaPhone(order.phone)!==phone)return bad('Order not found. Check the reference and checkout mobile number.',404);
 if(order.status!=='Paid'||order.fulfillmentStatus!=='Delivered')return bad('A return can only be requested after the order is marked delivered.',409);
 if(order.returnStatus)return bad('A return request already exists for this order.',409);
 const now=new Date().toISOString(),event={status:'ReturnRequested',at:now,actorId:'online-customer',actorName:order.customer,note:'Customer requested a return: '+reason};
 const updated={...order,returnStatus:'Requested',returnReason:reason,returnRequestedAt:now,fulfillmentStatus:'ReturnRequested',fulfillmentTimeline:[...(Array.isArray(order.fulfillmentTimeline)?order.fulfillmentTimeline:[]),event],updatedAt:now};
 const update=db.tx.update('web_orders',[{id:orderId,record:updated,if:{status:'Paid',fulfillmentStatus:'Delivered'}}]);
 const audit=db.tx.add('audit_logs',[{id:'online_order_event_'+token(18),ownerId:order.ownerId,actorId:'online-customer',actorName:order.customer,action:'ONLINE_ORDER_RETURN_REQUESTED',entity:'web_orders',recordId:orderId,details:{reason},createdAt:now}]);
 try{await db.transact([update,audit]);}catch{return bad('The order changed while the return was being submitted. Refresh tracking and try again.',409)}
 try{await publishShopEvent({ownerId:order.ownerId,eventId:'return_requested_'+orderId,eventType:'RETURN_REQUESTED',title:'Customer requested a return',body:order.customer+' requested a return for order '+orderId+'.'});}catch{}
 return res(200,{ok:true,order:{orderId,fulfillmentStatus:'ReturnRequested',returnStatus:'Requested',returnReason:reason,fulfillmentTimeline:updated.fulfillmentTimeline}});
}],
'POST /api/storefront/checkout':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<any>(ctx.body),ownerId=String(b.storeId||''),customer=String(b.customer||'').trim(),phone=normalizeGhanaPhone(b.phone),requestId=String(b.requestId||''),items=Array.isArray(b.items)?b.items:[],destination=obj<any>(b.destination);
 const destinationAddress=String(destination.address||'').trim(),destinationCity=String(destination.city||'').trim(),destinationRegion=String(destination.region||'').trim(),destinationPostalCode=String(destination.postalCode||'').trim(),destinationLandmark=String(destination.landmark||'').trim(),deliveryInstructions=String(destination.instructions||'').trim();
 if(!ownerId||ownerId.length>160||customer.length<2||customer.length>120||!phone||!/^[A-Za-z0-9_-]{16,80}$/.test(requestId)||!items.length||items.length>30)return bad('Enter a valid recipient name, Ghana mobile number and cart items.',400);
 if(destinationAddress.length<5||destinationAddress.length>500||destinationCity.length<2||destinationCity.length>100||destinationRegion.length<2||destinationRegion.length>100||destinationPostalCode.length>20||destinationLandmark.length>160||deliveryInstructions.length>500)return bad('Provide a complete delivery address, city or town and region. Check optional destination field lengths.',400);
 const orderId='weborder_'+requestId,[existing]=await db.get<any>('web_orders',[orderId],{consistent:true});
 if(existing){if(existing.ownerId!==ownerId||existing.customer!==customer||existing.phone!==phone||existing.destinationAddress!==destinationAddress||existing.destinationCity!==destinationCity||existing.destinationRegion!==destinationRegion||existing.destinationPostalCode!==destinationPostalCode||existing.destinationLandmark!==destinationLandmark||existing.deliveryInstructions!==deliveryInstructions)return bad('Checkout reference already used with different customer or destination details.',409);return res(200,{orderId,reference:existing.paystackReference||existing.mtnReference,status:existing.status,total:existing.total,replayed:true,authorizationUrl:existing.paystackAuthorizationUrl||null,paymentProvider:existing.paymentProvider||'MTN_COLLECTIONS'})}
 const products:Product[]=[],orderItems:any[]=[];let total=0;
 for(const item of items){
  const id=String(item.productId||''),qty=num(item.qty);
  if(!Number.isInteger(qty)||qty<1||qty>1000)return bad('Cart quantity is invalid.',400);
  const rawProduct=(await db.get<Product>('products',[id]))[0],p=rawProduct?{...rawProduct,id}:null;
  if(!p||p.ownerId!==ownerId||p.stock<qty)return bad('A product is unavailable or has insufficient stock. Refresh the catalogue and try again.',409);
  if(products.some(x=>x.id===p.id))return bad('Each product must appear only once in the cart.',400);
  products.push(p);orderItems.push({productId:p.id,name:p.name,qty,price:p.price});total+=p.price*qty;
 }
 total=Math.round(total*100)/100;
 const subtotal=total,promotionCode=String(b.promotionCode||'').trim().toUpperCase();let discount=0,promotion:any=null;if(promotionCode){promotion=await getCheckoutPromotion(ownerId,promotionCode);if(promotion?.error)return bad(promotion.error,400);discount=promotion.type==='percentage'?Math.round(total*Number(promotion.value))/100:Math.min(total,Number(promotion.value));discount=Math.round(Math.min(total,discount)*100)/100;total=Math.round((total-discount)*100)/100;}const smsOptIn=b.smsOptIn===true;

 const payment=await getWorkspaceActivePaymentProvider(ownerId);
 if(payment.activeProvider==='DISABLED')return bad('This shop has not selected a configured electronic payment provider. Contact the Managing Director before attempting online checkout.',503);
 if(payment.activeProvider==='PAYSTACK'){
  const email=validPaymentEmail(b.email);
  if(!email)return bad('Enter a valid email address for Paystack Mobile Money checkout.',400);
  const paystackNetwork=paystackMobileMoneyCode(b.mobileMoneyProvider);
  if(!paystackNetwork)return bad('Select MTN, AirtelTigo / ATMoney or Telecel for Paystack Mobile Money.',400);
  if(total<0.10)return bad('Paystack Ghana checkout requires a minimum order total of GHS 0.10.',400);
  const merchant=await loadWorkspacePaystackCredentials(ownerId);
  if(!merchant)return bad('This shop has no active Paystack production configuration. No MTN credentials will be used as a fallback.',503);
  const reference='SF'+crypto.randomUUID().replace(/-/g,'');
  const order={id:orderId,ownerId,customer,customerEmail:email,phone,smsOptIn,subtotal,discount,promotionCode,promotionId:promotion?.id||'',deliveryRecipient:customer,deliveryPhone:phone,destinationAddress,destinationCity,destinationRegion,destinationPostalCode,destinationLandmark,deliveryInstructions,items:orderItems,total,currency:'GHS',providerCurrency:'GHS',providerAmount:Math.round(total*100),payment:'Paystack Mobile Money',paymentProvider:'PAYSTACK',provider:'PAYSTACK',status:'Initiating',paystackReference:reference,paystackNetwork,paystackCredentialId:merchant.credentialId,paystackMerchantAccountId:merchant.merchantAccountId,paystackCallbackHost:merchant.pointer.callbackHost,paymentEnvironment:'production',requestId,createdAt:new Date().toISOString()};
  try{
   await db.transact([db.tx.add('web_orders',[order]),db.tx.add('integration_secrets',[{id:'paystack_ref_'+reference,recordType:'payment_reference_index',provider:'PAYSTACK',workspaceId:ownerId,ownerId,orderId,reference,credentialId:merchant.credentialId,createdAt:new Date().toISOString()}])]);
  }catch{
   const[raced]=await db.get<any>('web_orders',[orderId],{consistent:true});
   if(raced&&raced.ownerId===ownerId&&raced.paystackReference)return res(200,{orderId,reference:raced.paystackReference,status:raced.status,total:raced.total,authorizationUrl:raced.paystackAuthorizationUrl||null,replayed:true,paymentProvider:'PAYSTACK'});
   return bad('Checkout could not be safely recorded. No Paystack request was sent.',409);
  }

  try{
   const chargeResult=await requestPaystackMobileMoneyCharge({workspaceId:ownerId,credentialId:merchant.credentialId,merchantAccountId:merchant.merchantAccountId,email,phone:paystackLocalPhone(phone),network:paystackNetwork,amount:Math.round(total*100),reference,channel:'ONLINE_ORDER',entityId:orderId,customer});
   const now=new Date().toISOString();
   if(!chargeResult.ok){const failed={...order,status:chargeResult.unknown?'InitiationUnknown':'Failed',paystackHttpStatus:chargeResult.httpStatus,paystackOutcomeUnknown:chargeResult.unknown,failureReason:chargeResult.error,updatedAt:now};await setRecord('web_orders',orderId,failed);return res(chargeResult.unknown?503:502,{orderId,status:failed.status,error:chargeResult.error,retrySafe:false,message:'Do not submit another charge for this order. Check the original order reference first.'});}
   const providerStatus=String(chargeResult.data.status||'').toLowerCase(),displayText=String(chargeResult.data.display_text||chargeResult.payload.message||''),pending={...order,status:'Pending',paystackChargeStatus:providerStatus,paystackDisplayText:displayText,paymentRequestedAt:now,paystackAcceptedAt:now};
   if(!await setRecord('web_orders',orderId,pending))return bad('Paystack accepted the Mobile Money charge but ShopFlow could not save its status. Do not submit another charge; reconcile this order reference.',503);
   if(providerStatus==='success'){const verification=await routeHandler({httpMethod:'POST',path:'/api/storefront/order-status/reconcile',headers:{'content-type':'application/json'},queryStringParameters:{store:ownerId,order:orderId}});let result:any={};try{result=obj<any>(JSON.parse(verification?.body||'{}'))}catch{}return res(200,{orderId,reference,total,status:result.status||'Pending',paymentProvider:'PAYSTACK',authorizationInstructions:displayText,message:result.message||'Paystack charge submitted. Check the verified transaction status.'});}
   return res(202,{orderId,reference,total,currency:'GHS',providerAmount:order.providerAmount,providerCurrency:'GHS',status:'Pending',paymentProvider:'PAYSTACK',providerStatus,authorizationInstructions:displayText,message:providerStatus==='pay_offline'?(displayText||'Approve the Mobile Money authorization request on your phone.'):String(chargeResult.payload.message||'Paystack Mobile Money charge initiated. Follow the instructions to authorize payment.')});
  }catch(error){console.error('PAYSTACK_DIRECT_CHARGE_DIAGNOSTIC '+JSON.stringify({orderId,reference,at:new Date().toISOString()}));await setRecord('web_orders',orderId,{...order,status:'InitiationUnknown',failureReason:'Paystack direct charge outcome requires verification.',paystackOutcomeUnknown:true,updatedAt:new Date().toISOString()}).catch(()=>false);return res(503,{orderId,status:'InitiationUnknown',error:'Paystack did not return a conclusive Mobile Money charge response. Do not start another charge; check the original order reference first.'});}
 }

 const merchant=await loadWorkspaceMtnCredentials(ownerId);if(!merchant)return bad('This shop has not connected its own verified MTN Collections production account. Online payment is disabled until the Managing Director configures this workspace merchant account.',503);
 const callbackHost=normalizeMtnCallbackHost(merchant.pointer.callbackHost);if(!callbackHost||merchant.pointer.callbackHostRegistered!==true)return bad('This workspace has no confirmed MTN-registered public HTTPS callback hostname. The Managing Director must configure the exact hostname registered in the MTN Partner Portal before checkout can proceed.',503);
 const providerAmount=total;
 if(!Number.isFinite(providerAmount)||providerAmount<0.01)return bad('The payment amount is invalid.',400);
 const subscriptionKey=merchant.credentials.subscriptionKey;
 const order={id:orderId,ownerId,customer,phone,smsOptIn,subtotal,discount,promotionCode,promotionId:promotion?.id||'',deliveryRecipient:customer,deliveryPhone:phone,destinationAddress,destinationCity,destinationRegion,destinationPostalCode,destinationLandmark,deliveryInstructions,items:orderItems,total,currency:'GHS',providerCurrency:'GHS',providerAmount,payment:'MTN Mobile Money',paymentProvider:'MTN_COLLECTIONS',provider:'MTN_COLLECTIONS',status:'Initiating',mtnReference:crypto.randomUUID(),merchantAccountId:merchant.merchantAccountId,merchantCredentialId:merchant.credentialId,callbackHost,paymentEnvironment:'production',requestId,createdAt:new Date().toISOString()};
 const[createdOrderId]=await db.tx.add('web_orders',[order]);if(!createdOrderId){const[raced]=await db.get<any>('web_orders',[orderId],{consistent:true});if(raced&&raced.ownerId===ownerId&&raced.customer===customer&&raced.phone===phone&&raced.destinationAddress===destinationAddress&&raced.destinationCity===destinationCity&&raced.destinationRegion===destinationRegion&&raced.destinationPostalCode===destinationPostalCode&&raced.destinationLandmark===destinationLandmark&&raced.deliveryInstructions===deliveryInstructions&&raced.total===total&&JSON.stringify(raced.items)===JSON.stringify(orderItems))return res(200,{orderId,reference:raced.mtnReference,status:raced.status,total:raced.total,replayed:true});return bad('Checkout reference already exists or could not be committed. No second payment was initiated.',409)}
 let stage='credential_decryption';
 let providerHttpStatus:number|null=null;
 let providerErrorCode:string|undefined;
  let providerErrorMessage:string|undefined;
  let providerResponseSummary:string|undefined;
  let providerRejected=false;
  let providerAccepted=false;
 try{
  const credentials=merchant.credentials;
  if(!credentials.apiUser||!credentials.apiKey)throw new Error('credentials_unavailable');
  const base='https://momodeveloper.mtn.com';
  stage='oauth_token_request';
  const auth=await fetch(base+'/collection/token/',{method:'POST',headers:{'Ocp-Apim-Subscription-Key':subscriptionKey,'Authorization':'Basic '+btoa(credentials.apiUser+':'+credentials.apiKey)}});
  providerHttpStatus=auth.status;
  if(!auth.ok){const detail=await mtnProviderError(auth);providerErrorCode=detail.code;throw new Error('oauth_rejected');}
  stage='oauth_token_parse';
  const tokenData=obj<{access_token?:string}>(await auth.json());
  if(!tokenData.access_token)throw new Error('oauth_token_missing');
  const identity=await getShopIdentity(ownerId);
  stage='request_to_pay';
  providerHttpStatus=null;
  const callbackUrl='https://'+callbackHost+'/api/integrations/mtn/callback?order='+encodeURIComponent(orderId)+'&reference='+encodeURIComponent(order.mtnReference);
  const request=await fetch(base+'/collection/v1_0/requesttopay',{method:'POST',headers:{'Authorization':'Bearer '+tokenData.access_token,'X-Reference-Id':order.mtnReference,'X-Target-Environment':'production','Ocp-Apim-Subscription-Key':subscriptionKey,'Content-Type':'application/json','X-Callback-Url':callbackUrl},body:JSON.stringify({amount:providerAmount.toFixed(2),currency:'GHS',externalId:orderId,payer:{partyIdType:'MSISDN',partyId:phone.startsWith('0')?'233'+phone.slice(1):phone},payerMessage:mtnSafeNote(identity.shopName+' online order '+orderId),payeeNote:mtnSafeNote(identity.shopName+' order payment')})});
  providerHttpStatus=request.status;
  if(request.status!==202){const detail=await mtnProviderError(request);providerErrorCode=detail.code;providerErrorMessage=detail.message;providerResponseSummary=detail.bodySummary;providerRejected=detail.rejected;throw new Error('request_to_pay_unexpected_response');}
  providerAccepted=true;
  stage='persist_pending_order';
  const acceptedAt=new Date().toISOString();
  const markedPending=await setRecord('web_orders',orderId,{...order,status:'Pending',paymentRequestedAt:acceptedAt,mtnAcceptedAt:acceptedAt});
  if(!markedPending)throw new Error('pending_order_persistence_failed');
  return res(202,{orderId,reference:order.mtnReference,total,currency:'GHS',providerAmount,providerCurrency:'GHS',status:'Pending',message:'Your workspace merchant account accepted the MTN Collections payment request. Approve the Mobile Money prompt to complete payment.'});
 }catch(error){
  const definiteRejection=stage==='request_to_pay'&&(providerRejected||(providerHttpStatus!==null&&providerHttpStatus>=400&&providerHttpStatus<500&&providerHttpStatus!==409));
  const ambiguousOutcome=stage==='request_to_pay'&&!definiteRejection;
  const failureStatus=providerAccepted||ambiguousOutcome?'InitiationUnknown':'Failed';
  const diagnostic={stage,providerHttpStatus,providerErrorCode:providerErrorCode||null,providerErrorMessage:providerErrorMessage||null,providerResponseSummary:providerResponseSummary||null,providerRejected,providerAccepted,outcomeUnknown:ambiguousOutcome,orderId,reference:order.mtnReference,at:new Date().toISOString()};
  console.error('MTN_CHECKOUT_DIAGNOSTIC '+JSON.stringify(diagnostic));
  try{await setRecord('web_orders',orderId,{...order,status:failureStatus,failureReason:'MTN checkout '+(ambiguousOutcome?'outcome requires reconciliation':'was rejected')+' at '+stage,diagnosticStage:stage,providerHttpStatus,providerErrorCode:providerErrorCode||null,providerErrorMessage:providerErrorMessage||null,providerResponseSummary:providerResponseSummary||null,providerRejected,providerAccepted,providerOutcomeUnknown:ambiguousOutcome,updatedAt:new Date().toISOString()});}catch(persistError){console.error('MTN_CHECKOUT_DIAGNOSTIC_PERSIST_FAILED '+JSON.stringify({orderId,stage,providerAccepted,outcomeUnknown:ambiguousOutcome}));}
  if(providerAccepted)return res(503,{error:'MTN accepted the payment request, but ShopFlow could not confirm the order update. Do not start another checkout for this order.',orderId,status:'InitiationUnknown',retrySafe:false});
  if(ambiguousOutcome)return res(503,{error:'MTN response was inconclusive. ShopFlow will not submit another payment request. Check the original transaction status using this order reference.',orderId,status:'InitiationUnknown',retrySafe:false});
  return res(502,{error:'MTN rejected the payment request'+(providerErrorCode?' ('+providerErrorCode+')':'')+'. No payment prompt was accepted. You may retry with a new checkout after reviewing the integration settings.',orderId,status:'Failed',retrySafe:true,providerErrorCode:providerErrorCode||null});
 }
}],
'GET /api/storefront/order-status':[async ctx=>{
 const ownerId=String(ctx.event?.queryStringParameters?.store||''),orderId=String(ctx.event?.queryStringParameters?.order||'');
 if(!ownerId||!/^weborder_[A-Za-z0-9_-]{16,80}$/.test(orderId))return bad('Order reference is invalid.',400);
 const[order]=await db.get<any>('web_orders',[orderId],{consistent:true});
 if(!order||order.ownerId!==ownerId)return bad('Order not found.',404);
 return res(200,{orderId,status:order.status,total:order.total,receiptNumber:order.receiptNumber||null,message:order.status==='Paid'?'Payment confirmed.':order.status==='Failed'?'Payment failed.':'Payment status retrieved without initiating reconciliation.'});
}],
'POST /api/storefront/checkout/submit-otp':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<any>(ctx.body),ownerId=String(b.storeId||''),orderId=String(b.orderId||''),phone=normalizeGhanaPhone(b.phone),otp=String(b.otp||'').trim();
 if(!ownerId||!/^weborder_[A-Za-z0-9_-]{16,80}$/.test(orderId)||!phone||!/^[A-Za-z0-9]{4,12}$/.test(otp))return bad('Enter a valid order, checkout mobile number and network authorization code.',400);
 const [order]=await db.get<any>('web_orders',[orderId],{consistent:true});
 if(!order||order.ownerId!==ownerId||normalizeGhanaPhone(order.phone)!==phone||order.paymentProvider!=='PAYSTACK'||!order.paystackReference)return bad('Paystack order was not found for this checkout mobile number.',404);
 if(String(order.paystackChargeStatus||'').toLowerCase()!=='send_otp')return bad('This order is not waiting for an authorization code. Check its current status.',409);
 const submitted=await submitPaystackMobileMoneyOtp({workspaceId:ownerId,credentialId:String(order.paystackCredentialId),merchantAccountId:String(order.paystackMerchantAccountId),reference:String(order.paystackReference),otp});
 if(!submitted.ok)return bad(submitted.error,submitted.httpStatus>=500?502:400);
 const providerStatus=String(submitted.data.status||'').toLowerCase(),displayText=String(submitted.data.display_text||submitted.payload.message||''),updated={...order,status:'Pending',paystackChargeStatus:providerStatus,paystackDisplayText:displayText,otpSubmittedAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
 await setRecord('web_orders',orderId,updated);
 if(providerStatus==='success'){const verification=await routeHandler({httpMethod:'POST',path:'/api/storefront/order-status/reconcile',headers:{'content-type':'application/json'},queryStringParameters:{store:ownerId,order:orderId}});let result:any={};try{result=obj<any>(JSON.parse(verification?.body||'{}'))}catch{}return res(200,{orderId,status:result.status||'Pending',providerStatus,authorizationInstructions:displayText,message:result.message||'Authorization code accepted. Checking verified payment status.'});}
 return res(200,{orderId,status:'Pending',providerStatus,authorizationInstructions:displayText,message:displayText||'Authorization code submitted. Complete any remaining steps on the customer’s phone, then check payment status.'});
}],
'POST /api/storefront/order-status/reconcile':[async ctx=>{
 const ownerId=String(ctx.event?.queryStringParameters?.store||''),orderId=String(ctx.event?.queryStringParameters?.order||'');
 if(!ownerId||!/^weborder_[A-Za-z0-9_-]{16,80}$/.test(orderId))return bad('Order reference is invalid.',400);
 const [order]=await db.get<any>('web_orders',[orderId],{consistent:true});
 if(!order||order.ownerId!==ownerId)return bad('Order not found.',404);
 const legacyAmbiguous=order.status==='Failed'&&order.diagnosticStage==='request_to_pay'&&order.providerHttpStatus===200&&order.providerAccepted!==true;
 if(['Paid','Failed','Cancelled'].includes(order.status)&&!legacyAmbiguous)return res(200,{orderId,status:order.status,total:order.total,receiptNumber:order.receiptNumber||null});
 if(order.status!=='Pending'&&order.status!=='InitiationUnknown'&&order.status!=='Initiating'&&!legacyAmbiguous)return res(200,{orderId,status:order.status,total:order.total});

 if(order.paymentProvider==='PAYSTACK'){
  const merchant=await loadWorkspacePaystackCredentials(ownerId,order.paystackCredentialId);
  if(!merchant||merchant.merchantAccountId!==order.paystackMerchantAccountId||order.paymentEnvironment!=='production'||order.providerCurrency!=='GHS'||!order.paystackReference)return bad('The original workspace Paystack credentials for this order are unavailable. No MTN or other merchant credentials will be used.',503);
  try{
   const response=await fetch('https://api.paystack.co/transaction/verify/'+encodeURIComponent(order.paystackReference),{headers:{Authorization:'Bearer '+merchant.credentials.secretKey}});
   if(response.status===404){await setRecord('web_orders',orderId,{...order,status:'Failed',failureReason:'Paystack has no transaction for the original reference.',paystackStatusHttpStatus:404,updatedAt:new Date().toISOString()});return res(200,{orderId,status:'Failed',total:order.total,retrySafe:true,message:'Paystack has no transaction for this reference. No payment was accepted; you may start a new checkout.'})}
   if(!response.ok)return bad('Paystack payment status could not be verified. Keep this order reference and retry; do not create another payment.',502);
   const payload=obj<any>(await response.json()),result=payload.data||{};
   if(payload.status!==true||String(result.reference||'')!==String(order.paystackReference))return bad('Paystack verification response did not match the original order reference.',409);
   if(String(result.currency||'').toUpperCase()!=='GHS'||Math.round(Number(result.amount))!==Math.round(Number(order.total)*100))return bad('Paystack payment amount or currency does not match this order. Payment was not marked as paid.',409);
   const status=String(result.status||'').toLowerCase();
   if(status==='success')return await finalizePaidOnlineOrder(order,order.paystackReference,String(result.id||''),'Paystack');
   if(['failed','abandoned','reversed','expired'].includes(status)){await setRecord('web_orders',orderId,{...order,status:'Failed',failureReason:String(result.gateway_response||status).slice(0,240),paystackStatus:status,paystackStatusCheckedAt:new Date().toISOString(),updatedAt:new Date().toISOString()});return res(200,{orderId,status:'Failed',total:order.total,message:'Paystack did not complete this payment. No stock was deducted.'})}
   if(order.status==='InitiationUnknown'||order.status==='Initiating')await setRecord('web_orders',orderId,{...order,status:'Pending',paystackStatus:status,paystackStatusCheckedAt:new Date().toISOString()});
   return res(200,{orderId,status:'Pending',total:order.total,providerStatus:status,authorizationInstructions:order.paystackDisplayText||'',message:order.paystackDisplayText||'Paystack payment is still pending. Complete the authorization process and check again.'});
  }catch(error){console.error('PAYSTACK_STATUS_DIAGNOSTIC '+JSON.stringify({orderId,reference:order.paystackReference}));return bad('Paystack payment verification is temporarily unavailable. Retry shortly.',502)}
 }

 const merchant=await loadWorkspaceMtnCredentials(ownerId,order.merchantCredentialId);if(!merchant||merchant.merchantAccountId!==order.merchantAccountId||order.paymentEnvironment!=='production'||order.providerCurrency!=='GHS')return bad('The original workspace merchant credentials for this payment are unavailable. No other merchant account will be used.',503);
 const subscriptionKey=merchant.credentials.subscriptionKey;
 try{
  const credentials=merchant.credentials;
  const base='https://momodeveloper.mtn.com';
  const auth=await fetch(base+'/collection/token/',{method:'POST',headers:{'Ocp-Apim-Subscription-Key':subscriptionKey,'Authorization':'Basic '+btoa(String(credentials.apiUser)+':'+String(credentials.apiKey))}});
  if(!auth.ok)return bad('MTN payment status could not be checked yet. Retry shortly.',502);
  const tokenData=obj<{access_token?:string}>(await auth.json());if(!tokenData.access_token)return bad('MTN payment status could not be checked yet. Retry shortly.',502);
  const check=await fetch(base+'/collection/v1_0/requesttopay/'+order.mtnReference,{headers:{'Authorization':'Bearer '+tokenData.access_token,'X-Target-Environment':'production','Ocp-Apim-Subscription-Key':subscriptionKey}});
  if(!check.ok){
   const detail=await mtnProviderError(check);
   if(check.status===404){
    await setRecord('web_orders',orderId,{...order,status:'Failed',failureReason:'MTN returned RESOURCE_NOT_FOUND for the original reference; no transaction was accepted.',providerStatusHttpStatus:404,providerStatusCheckedAt:new Date().toISOString(),updatedAt:new Date().toISOString()});
    return res(200,{orderId,status:'Failed',total:order.total,currency:order.currency||'GHS',retrySafe:true,message:'MTN has no transaction for the original reference. No payment was accepted; you may start a new checkout.'});
   }
   console.error('MTN_STATUS_DIAGNOSTIC '+JSON.stringify({orderId,reference:order.mtnReference,httpStatus:detail.httpStatus,code:detail.code||null,message:detail.message||null}));
   return bad('MTN payment status could not be checked yet. Keep this order reference and retry the status check; do not start another payment.',502);
  }
  const result=obj<{status?:string;financialTransactionId?:string;reason?:{message?:string}}>(await check.json()),providerStatus=String(result.status||'').toUpperCase();
  if(providerStatus==='SUCCESSFUL'){
   const currentProducts:Product[]=[];
   for(const item of order.items){const p=(await db.get<Product>('products',[item.productId]))[0];if(!p||p.ownerId!==ownerId||p.stock<item.qty)return bad('Payment succeeded but inventory needs staff reconciliation. Contact the shop and keep order reference '+orderId+'.',409);currentProducts.push(p)}
   const now=new Date().toISOString(),receipt=docNo('WEB');
   const ops:any[]=[];
   for(let i=0;i<order.items.length;i++){
    const item=order.items[i],p=currentProducts[i];
    ops.push(db.tx.update('products',[{id:item.productId,record:{...p,stock:p.stock-item.qty,updatedAt:now},if:{stock:p.stock}}]));
    ops.push(db.tx.add('stock_moves',[{id:'webmove_'+orderId+'_'+i,productId:item.productId,productName:item.name,type:'OUT',qty:item.qty,reason:'Paid online order '+receipt,actorName:'Online checkout',ownerId,createdAt:now}]));
   }
   const saleId='websale_'+orderId,receiptId='receipt_'+saleId,shopIdentity=await getShopIdentity(ownerId);
   ops.push(db.tx.add('sales',[{id:saleId,number:receipt,requestId:order.requestId,items:order.items,total:order.total,payment:'MTN Mobile Money',customer:order.customer,customerPhone:order.phone,createdAt:now,ownerId,agentName:'Online customer',channel:'Online',providerReference:order.mtnReference,financialTransactionId:result.financialTransactionId||''}]));
   const receiptRecord={id:receiptId,ownerId,saleId,receiptNumber:receipt,number:receipt,storeName:shopIdentity.shopName,tagline:shopIdentity.tagline,city:shopIdentity.city,customer:order.customer,paymentMethod:'MTN Mobile Money',paymentStatus:'Received',items:(order.items||[]).map((item:any)=>({productId:item.productId,name:item.name,qty:item.qty,unitPrice:item.price,lineTotal:Math.round(Number(item.price||0)*Number(item.qty||0)*100)/100})),subtotal:Number(order.subtotal??order.total),discount:Number(order.discount||0),tax:0,total:order.total,currency:'GHS',cashierName:'Online checkout',issuedAt:now,createdAt:now,channel:'Online',providerReference:order.mtnReference,financialTransactionId:result.financialTransactionId||''};
   ops.push(db.tx.add('receipts',[receiptRecord]));
   ops.push(db.tx.update('web_orders',[{id:orderId,record:{...order,status:'Paid',paymentStatus:'Paid',receiptNumber:receipt,financialTransactionId:result.financialTransactionId||'',paidAt:now,fulfillmentStatus:'Processing',fulfillmentTimeline:[{status:'Processing',at:now,actorName:'ShopFlow',note:'Payment confirmed. The order is awaiting seller processing.'}]},if:{status:order.status}}]));
   try{await db.transact(ops)}catch{
    const [recovered]=await db.get<any>('web_orders',[orderId],{consistent:true});
    if(recovered?.status!=='Paid')return bad('MTN reported payment success, but the order could not be finalized automatically. Contact the shop with order reference '+orderId+'.',409);
    return res(200,{orderId,status:'Paid',total:recovered.total,receiptNumber:recovered.receiptNumber,replayed:true});
   }
   const customers=await owned<Customer>('customers',ownerId),existing=customers.find(c=>c.name.toLowerCase()===order.customer.toLowerCase());
   if(existing)await setRecord('customers',existing.id!,{...existing,visits:existing.visits+1,lifetimeValue:(existing.lifetimeValue||0)+order.total});
   else await create('customers',{name:order.customer,phone:order.phone,visits:1,lifetimeValue:order.total,ownerId});
   await create('audit_logs',{ownerId,actorId:'online-customer',actorName:order.customer,action:'ONLINE_ORDER_PAID',entity:'web_orders',recordId:orderId,receiptNumber:receipt,providerReference:order.mtnReference,createdAt:now});
   try{await publishShopEvent({ownerId,eventId:'online_paid_'+orderId,eventType:'ONLINE_ORDER_PAID',title:'Online order paid',body:'Order '+receipt+' has been paid and is ready for processing.',phone:order.phone,consent:order.smsOptIn===true,sms:'Payment confirmed for order '+receipt+'. Amount GHS '+Number(order.total).toFixed(2)+'. The shop is preparing your order.'});}catch{}
   return res(200,{orderId,status:'Paid',paymentStatus:'Paid',fulfillmentStatus:'Processing',total:order.total,receiptNumber:receipt});
  }
  if(['FAILED','REJECTED','TIMEOUT','EXPIRED'].includes(providerStatus)){
   await setRecord('web_orders',orderId,{...order,status:'Failed',failureReason:result.reason?.message||'MTN payment failed',updatedAt:new Date().toISOString()});
   return res(200,{orderId,status:'Failed',total:order.total,message:'MTN did not complete the payment. No stock was deducted.'});
  }
  if(order.status==='InitiationUnknown'||order.status==='Initiating'||legacyAmbiguous)await setRecord('web_orders',orderId,{...order,status:'Pending',lastStatusCheckedAt:new Date().toISOString()});
  return res(200,{orderId,status:'Pending',total:order.total,message:'Payment is still pending. Approve the MoMo prompt, then check again.'});
 }catch{return bad('Payment status is temporarily unavailable. Retry shortly.',502)}
}],
'GET /api/shop/online-orders':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);
 if(!permit(s,'online-orders',true))return bad('Your role does not have permission to manage online orders.',403);
 const ownerId=s.user.ownerId||s.userId,items=await owned<any>('web_orders',ownerId),visible=items.sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,250);
 return res(200,{items:visible.map(x=>({...x,customerPhone:x.phone||'',fulfillmentStatus:x.fulfillmentStatus||null,fulfillmentTimeline:Array.isArray(x.fulfillmentTimeline)?x.fulfillmentTimeline:[]})),total:visible.length});
}],
'POST /api/shop/online-orders/update':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'online-orders');if(denied)return denied;
 const b=obj<any>(ctx.body),id=String(b.orderId||''),next=String(b.fulfillmentStatus||''),note=String(b.note||'').trim().slice(0,240),ownerId=s.user.ownerId||s.userId;
 const [order]=await db.get<any>('web_orders',[id],{consistent:true});
 if(!order||order.ownerId!==ownerId||order.status!=='Paid')return bad('Paid online order not found.',404);
 const current=String(order.fulfillmentStatus||'Processing');
 const transitions:Record<string,string[]>={Processing:['Packed'],Packed:['Dispatched'],Dispatched:['InTransit'],InTransit:['OutForDelivery'],OutForDelivery:['Delivered','DeliveryFailed'],DeliveryFailed:['OutForDelivery'],ReturnRequested:['ReturnApproved','ReturnRejected'],ReturnApproved:['ReturnInTransit'],ReturnInTransit:['Returned']};
 if(!(transitions[current]||[]).includes(next))return bad('This fulfilment status transition is not allowed.',409);
 const courierName=String(b.courierService||b.courierName||order.courierName||'').trim().slice(0,100);
 const referenceSuffix=String(id).replace(/[^A-Za-z0-9]/g,'').slice(-12).toUpperCase();
 const trackingNumber=String(order.trackingNumber||'SHP-'+referenceSuffix).trim().slice(0,100);
 const dispatchReference=String(order.dispatchReference||'DSP-'+referenceSuffix).trim().slice(0,100);
 const estimatedDelivery=String(b.expectedDelivery||b.estimatedDelivery||'').trim();
 const dispatchDetails=next==='Dispatched'?{
  courierService:courierName,courierType:String(order.courierType||b.courierType||'').trim().slice(0,60),
  courierContact:String(order.courierContact||b.courierContact||'').trim().slice(0,100),courierPhone:String(order.courierPhone||b.courierPhone||'').trim().slice(0,30),
  courierEmail:String(order.courierEmail||b.courierEmail||'').trim().slice(0,120),pickupAddress:String(order.pickupAddress||b.pickupAddress||'').trim().slice(0,180),
  deliveryRecipient:String(order.deliveryRecipient||b.recipientName||b.deliveryRecipient||order.customer||'').trim().slice(0,120),deliveryPhone:String(order.deliveryPhone||b.recipientPhone||b.deliveryPhone||order.phone||'').trim().slice(0,30),
  destinationAddress:String(order.destinationAddress||b.destinationAddress||'').trim().slice(0,500),destinationCity:String(order.destinationCity||b.destinationCity||'').trim().slice(0,100),
  destinationRegion:String(order.destinationRegion||b.destinationRegion||'').trim().slice(0,100),destinationPostalCode:String(order.destinationPostalCode||b.destinationPostalCode||'').trim().slice(0,20),destinationLandmark:String(order.destinationLandmark||b.destinationLandmark||'').trim().slice(0,160),deliveryInstructions:String(order.deliveryInstructions||b.deliveryInstructions||'').trim().slice(0,500),
  packageCount:Number(order.packageCount||1),packageDescription:String(order.packageDescription||((order.items||[]).map((item:any)=>String(item.name||'')+' × '+Number(item.qty||0)).join(', '))).trim().slice(0,500),
  packageWeight:order.packageWeight!==undefined&&order.packageWeight!==null?Number(order.packageWeight):(b.packageWeight===''||b.packageWeight==null?null:Number(b.packageWeight)),
  deliveryFee:order.deliveryFee!==undefined&&order.deliveryFee!==null?Number(order.deliveryFee):(b.deliveryFee===''||b.deliveryFee==null?null:Number(b.deliveryFee)),
  declaredValue:Number(order.total),
  handlingInstructions:String(order.handlingInstructions||'Handle with care').trim().slice(0,100),
  shippingMethod:String(order.shippingMethod||'Standard delivery').trim().slice(0,80),dispatchNotes:String(b.dispatchNotes||'').trim().slice(0,500)
 }:{};
 if(next==='Dispatched'){
  const courierDigits=dispatchDetails.courierPhone.replace(/[^0-9]/g,'');
  if(courierName.length<2||courierName.length>100||!['Courier company','Local dispatch rider','Shop-owned delivery','Third-party logistics','Customer pickup','Other'].includes(dispatchDetails.courierType)||courierDigits.length<7||courierDigits.length>15||dispatchDetails.courierContact.length>100||dispatchDetails.courierEmail.length>120||(dispatchDetails.courierEmail&&(!dispatchDetails.courierEmail.includes('@')||dispatchDetails.courierEmail.lastIndexOf('.')<dispatchDetails.courierEmail.indexOf('@')+2))||dispatchDetails.pickupAddress.length<5||dispatchDetails.pickupAddress.length>180||dispatchDetails.deliveryRecipient.length<2||dispatchDetails.deliveryPhone.length<7||dispatchDetails.destinationAddress.length<5||dispatchDetails.destinationCity.length<2||dispatchDetails.destinationRegion.length<2||dispatchDetails.destinationPostalCode.length>20||dispatchDetails.destinationLandmark.length>160||dispatchDetails.deliveryInstructions.length>500||trackingNumber.length<3||trackingNumber.length>100||dispatchReference.length<3||dispatchReference.length>100)return bad('Complete valid courier and shipment details. Recipient and destination data must be present on the original order.',400);
  if(!Number.isInteger(dispatchDetails.packageCount)||dispatchDetails.packageCount<1||dispatchDetails.packageCount>100)return bad('Package count must be between 1 and 100.',400);
  if([dispatchDetails.packageWeight,dispatchDetails.deliveryFee,dispatchDetails.declaredValue].some(v=>v!==null&&(!Number.isFinite(v)||v<0)))return bad('Package weight, delivery fee and declared value must be valid non-negative amounts.',400);
  if(!dispatchDetails.packageDescription||dispatchDetails.packageDescription.length>500||dispatchDetails.handlingInstructions.length>100||dispatchDetails.shippingMethod.length>80||dispatchDetails.dispatchNotes.length>500)return bad('Shipment description or handling fields are invalid.',400);
 }
 if(estimatedDelivery&&(!/^\d{4}-\d{2}-\d{2}$/.test(estimatedDelivery)||!Number.isFinite(Date.parse(estimatedDelivery+'T00:00:00Z'))||estimatedDelivery<new Date().toISOString().slice(0,10)))return bad('Expected delivery date must be a real date today or later.',400);
 const now=new Date().toISOString();
 const dispatchNote=next==='Dispatched'?'Dispatched via '+courierName+' · Tracking '+trackingNumber+' · Reference '+dispatchReference+(dispatchDetails.destinationCity?', to '+dispatchDetails.destinationCity:'')+(dispatchDetails.dispatchNotes?' · '+dispatchDetails.dispatchNotes:''):({InTransit:'Shipment is in transit.',OutForDelivery:'Courier is delivering the order.',Delivered:'Order delivery confirmed.',DeliveryFailed:'Delivery attempt was unsuccessful.',ReturnApproved:'Return request approved by the shop.',ReturnRejected:'Return request reviewed and declined.',ReturnInTransit:'Returned item is on its way back to the shop.',Returned:'Returned item received by the shop.'}[next]||'');
 const event={status:next,at:now,actorId:s.userId,actorName:s.user.name,note:note||dispatchNote||({Packed:'Items packed and ready for dispatch.',Dispatched:'Order handed to the courier.',OutForDelivery:'Courier is delivering the order.',Delivered:'Order delivery confirmed.',DeliveryFailed:'Delivery attempt was unsuccessful.'}[next]||'Order status updated.')};
 const updated={...order,fulfillmentStatus:next,returnStatus:next==='ReturnApproved'?'Approved':next==='ReturnRejected'?'Rejected':next==='Returned'?'Received':order.returnStatus||null,fulfillmentTimeline:[...(Array.isArray(order.fulfillmentTimeline)?order.fulfillmentTimeline:[]),event],courierName,trackingNumber,dispatchReference,estimatedDelivery:estimatedDelivery||order.estimatedDelivery||'',...(next==='Dispatched'?{...dispatchDetails,dispatchedAt:now}:{}),...(next==='Delivered'?{deliveredAt:now}:{}),...(next==='Returned'?{returnedAt:now}:{}),updatedAt:now};
 const update=db.tx.update('web_orders',[{id,record:updated,if:{status:'Paid',fulfillmentStatus:order.fulfillmentStatus}}]);
 const audit=db.tx.add('audit_logs',[{id:'online_order_event_'+token(18),ownerId,actorId:s.userId,actorName:s.user.name,action:'ONLINE_ORDER_'+next.toUpperCase(),entity:'web_orders',recordId:id,details:{from:current,to:next,trackingNumber:next==='Dispatched'?trackingNumber:undefined,dispatchReference:next==='Dispatched'?dispatchReference:undefined},createdAt:now}]);
 try{await db.transact([update,audit]);}catch{return bad('Order status changed concurrently or the update could not be committed. Refresh the order and retry.',409)}
 try{await publishShopEvent({ownerId,eventId:'fulfilment_'+id+'_'+next,eventType:'ORDER_'+next.toUpperCase(),title:'Order '+next,body:'Order '+(order.receiptNumber||id)+' is now '+next+'.',phone:order.phone,consent:order.smsOptIn===true,sms:'Order '+(order.receiptNumber||id)+' update: '+next+'.'});}catch{}
 return res(200,{ok:true,order:{...updated,orderId:id}});
}],


'GET /api/push/vapid-public-key':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);try{return res(200,{publicKey:(await getVapidKeys()).publicKey});}catch{return bad('VAPID key setup is unavailable.',503);}}],
'POST /api/push/subscribe':[async ctx=>{const s=await session(ctx);if(!s)return bad('Session or CSRF token is invalid.',403);const sub=obj<any>(obj<any>(ctx.body).subscription),endpoint=String(sub.endpoint||''),keys=obj<any>(sub.keys);if(!endpoint.startsWith('https://')||endpoint.length>2048||!keys.p256dh||!keys.auth)return bad('Push subscription is invalid.',400);const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(endpoint))),hash=Array.from(digest,x=>x.toString(16).padStart(2,'0')).join(''),id='push_'+hash.slice(0,48),ownerId=s.user.ownerId||s.userId,r={id,ownerId,userId:s.userId,endpoint,keys:{p256dh:String(keys.p256dh),auth:String(keys.auth)},updatedAt:new Date().toISOString()},[old]=await db.get<any>('push_subscriptions',[id],{consistent:true}),ok=old?await setRecord('push_subscriptions',id,r):!!(await db.tx.add('push_subscriptions',[r]))[0];return ok?res(200,{ok:true}):bad('Push subscription could not be saved.',500);}],
'GET /api/shop/notifications':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);const items=(await owned<any>('notifications',s.user.ownerId||s.userId)).filter(x=>x.userId===s.userId).sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,100);return res(200,{items:clean(items),unread:items.filter(x=>!x.readAt).length});}],
'POST /api/shop/notifications/read':[async ctx=>{const s=await session(ctx);if(!s)return bad('Session or CSRF token is invalid.',403);const id=String(obj<any>(ctx.body).id||''),[n]=await db.get<any>('notifications',[id],{consistent:true});if(!n||n.ownerId!==(s.user.ownerId||s.userId)||n.userId!==s.userId)return bad('Notification not found.',404);if(!n.readAt)await setRecord('notifications',id,{...n,readAt:new Date().toISOString()});return res(200,{ok:true});}],
'GET /api/shop/transactions':[async ctx=>{const s=await session(ctx,false),denied=guard(ctx,s,'sales',false);if(denied)return denied;const ownerId=s.user.ownerId||s.userId,sales=await owned<any>('sales',ownerId),orders=await owned<any>('web_orders',ownerId),attempts=await owned<any>('payment_records',ownerId),rows:any[]=sales.map(x=>({...x,transactionId:x.id||x.number,recordType:'sale',transactionStatus:'Paid',channel:x.channel||'POS',transactionDate:x.createdAt}));for(const o of orders.filter(x=>x.status!=='Paid'))rows.push({transactionId:o.id,recordType:'online_order',transactionStatus:o.status,channel:'ONLINE_ORDER',customer:o.customer,total:o.total,paymentProvider:o.paymentProvider,providerReference:o.paystackReference||o.mtnReference,transactionDate:o.createdAt,ownerId});for(const a of attempts.filter(x=>String(x.id||'').startsWith('pospay_')&&x.status!=='Paid'))rows.push({transactionId:a.id,recordType:'payment_attempt',transactionStatus:a.status,channel:'POS',customer:a.customer,total:a.total,paymentProvider:a.paymentProvider,providerReference:a.paystackReference||a.mtnReference,transactionDate:a.createdAt,ownerId});rows.sort((a,b)=>String(b.transactionDate||'').localeCompare(String(a.transactionDate||'')));return res(200,{items:clean(rows.slice(0,500)),total:rows.length,limit:500});}],
'GET /api/integrations/sms/status':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Managing Director')return bad('Only the Managing Director can manage SMS.',403);const ownerId=s.user.ownerId||s.userId,[p]=await db.get<any>('integration_secrets',['hubtel_sms_workspace_'+ownerId],{consistent:true});return res(200,{configured:!!p&&p.status==='active'&&p.workspaceId===ownerId&&!!p.activeCredentialId,senderId:p?.senderId||''});}],
'POST /api/integrations/sms/configure':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can configure SMS.',403);const b=obj<any>(ctx.body),ownerId=s.user.ownerId||s.userId,clientId=String(b.clientId||'').trim(),clientSecret=String(b.clientSecret||'').trim(),senderId=String(b.senderId||'').trim();if(clientId.length<3||clientId.length>128||clientSecret.length<8||clientSecret.length>256||!/^[A-Za-z0-9]{1,11}$/.test(senderId))return bad('Enter valid Hubtel credentials and approved sender ID.',400);const master=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'),pid='hubtel_sms_workspace_'+ownerId,[old]=await db.get<any>('integration_secrets',[pid],{consistent:true}),cid='hubtel_sms_cred_'+token(18),encrypted=await encryptWorkspacePaymentCredentials(JSON.stringify({clientId,clientSecret,senderId}),master,ownerId,cid),now=new Date().toISOString(),credential={id:cid,workspaceId:ownerId,ownerId,provider:'HUBTEL_SMS',merchantAccountId:'hubtel_sms_'+ownerId,status:'active',...encrypted,createdAt:now};const[created]=await db.tx.add('integration_secrets',[credential]);if(!created)return bad('SMS credentials could not be stored.',500);const pointer={id:pid,workspaceId:ownerId,ownerId,provider:'HUBTEL_SMS',status:'active',activeCredentialId:cid,senderId,createdAt:old?.createdAt||now,updatedAt:now},ok=old?await setRecord('integration_secrets',pid,pointer):!!(await db.tx.add('integration_secrets',[pointer]))[0];return ok?res(200,{configured:true,senderId}):bad('SMS configuration failed.',500);}],
'POST /api/integrations/sms/test':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can test SMS.',403);const phone=normalizeGhanaPhone(obj<any>(ctx.body).phone);if(!phone)return bad('Enter a valid Ghana mobile number.',400);const ok=await hubtelSms(s.user.ownerId||s.userId,phone,'ShopFlow SMS integration test. No action is required.','test_'+token(18));return ok?res(200,{ok:true}):bad('Hubtel did not accept the test SMS.',502);}],
'GET /api/integrations/payments/status':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Managing Director')return bad('Only the Managing Director can manage payment integrations.',403);
 const ownerId=s.user.ownerId||s.userId,payment=await getWorkspaceActivePaymentProvider(ownerId);
 return res(200,{selectedProvider:payment.activeProvider,mtnConfigured:payment.mtnReady,paystackConfigured:payment.paystackReady,paystackWebhookUrl:payment.paystack?.webhookUrl||'',paystackCallbackUrl:payment.paystack?.callbackUrl||'',callbackHost:payment.paystack?.callbackHost||'',webhookHostRegistered:payment.paystack?.webhookHostRegistered===true});
}],
'POST /api/integrations/payments/provider':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can choose the workspace payment provider.',403);
 const ownerId=s.user.ownerId||s.userId,provider=String(obj<any>(ctx.body).provider||'');
 if(!['MTN_COLLECTIONS','PAYSTACK','DISABLED'].includes(provider))return bad('Choose MTN Collections, Paystack or Disabled.',400);
 const availability=await getWorkspaceActivePaymentProvider(ownerId);
 if(provider==='MTN_COLLECTIONS'&&!availability.mtnReady)return bad('Configure this workspace’s MTN Collections production account and registered callback host before selecting it.',409);
 if(provider==='PAYSTACK'&&!availability.paystackReady)return bad('Configure this workspace’s Paystack production account and registered webhook before selecting it.',409);
 const id='payment_provider_'+ownerId,[old]=await db.get<any>('integration_secrets',[id],{consistent:true}),record={id,workspaceId:ownerId,ownerId,recordType:'workspace_payment_provider_selection',activeProvider:provider,updatedAt:new Date().toISOString(),updatedBy:s.userId,createdAt:old?.createdAt||new Date().toISOString()};
 const saved=old?await setRecord('integration_secrets',id,record):!!(await db.tx.add('integration_secrets',[record]))[0];
 if(!saved)return bad('The active electronic payment provider could not be changed.',500);
 await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'WORKSPACE_PAYMENT_PROVIDER_CHANGED',entity:'payment_integrations',recordId:id,details:{provider},createdAt:new Date().toISOString()});
 return res(200,{ok:true,selectedProvider:provider,message:provider==='DISABLED'?'Electronic payments have been disabled for new online orders.':'New online orders will use '+(provider==='PAYSTACK'?'Paystack':'MTN Collections')+'. Existing orders remain bound to their original provider.'});
}],
'GET /api/integrations/paystack/status':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Managing Director')return bad('Only the Managing Director can manage payment integrations.',403);
 const ownerId=s.user.ownerId||s.userId,[pointer]=await db.get<any>('integration_secrets',['paystack_workspace_'+ownerId],{consistent:true});
 const configured=!!pointer&&pointer.status==='active'&&pointer.provider==='PAYSTACK'&&pointer.workspaceId===ownerId&&!!pointer.activeCredentialId;
 return res(200,{environment:'production',configured,webhookUrl:configured?pointer.webhookUrl:'',callbackUrl:configured?pointer.callbackUrl:'',callbackHost:configured?pointer.callbackHost:'',webhookHostRegistered:configured&&pointer.webhookHostRegistered===true});
}],
'POST /api/integrations/paystack/configure':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can configure this workspace Paystack account.',403);
 const b=obj<any>(ctx.body),ownerId=s.user.ownerId||s.userId,secretKey=String(b.secretKey||'').trim(),callbackHost=normalizeMtnCallbackHost(b.callbackHost);
 if(!/^sk_live_[A-Za-z0-9_-]{12,256}$/.test(secretKey)||!callbackHost||b.webhookHostRegistered!==true||b.settlementDestinationVerified!==true)return bad('Enter a valid Paystack live secret key, the public HTTPS callback hostname, and confirm webhook registration and settlement ownership.',400);
 const names=await secrets.listSecretNames();if(!names.includes('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'))return bad('Workspace credential encryption is unavailable. Contact the platform administrator.',503);
 const masterKey=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY');if(masterKey.length<32)return bad('Workspace credential encryption key is invalid.',503);
 try{
  const check=await fetch('https://api.paystack.co/balance',{headers:{Authorization:'Bearer '+secretKey}});
  const payload=obj<any>(await check.json().catch(()=>({})));
  if(!check.ok||payload.status!==true)return bad('Paystack could not authenticate this live secret key. Verify the key in the shop’s Paystack dashboard.',502);
  const balances=Array.isArray(payload.data)?payload.data:[];
  if(balances.length&&!balances.some((entry:any)=>String(entry.currency||'').toUpperCase()==='GHS'))return bad('This Paystack account does not expose a GHS balance. Confirm that its Ghana cedi payment capability is enabled.',409);
 }catch(error){return bad('Paystack credential verification is temporarily unavailable. No credentials were activated.',502)}
 const pointerId='paystack_workspace_'+ownerId,[oldPointer]=await db.get<any>('integration_secrets',[pointerId],{consistent:true}),merchantAccountId='paystackmerchant_'+ownerId,credentialId='paystackcred_'+token(18),encrypted=await encryptWorkspacePaymentCredentials(JSON.stringify({secretKey}),masterKey,ownerId,credentialId),now=new Date().toISOString();
 const credential={id:credentialId,workspaceId:ownerId,ownerId,merchantAccountId,provider:'PAYSTACK',environment:'production',status:'active',...encrypted,createdAt:now,createdBy:s.userId};
 const[created]=await db.tx.add('integration_secrets',[credential]);if(!created)return bad('Paystack credentials could not be encrypted and stored. The existing configuration was not changed.',500);
 const base='https://'+callbackHost,pointer={id:pointerId,workspaceId:ownerId,ownerId,merchantAccountId,provider:'PAYSTACK',environment:'production',status:'active',activeCredentialId:credentialId,callbackHost,callbackUrl:base+'/api/integrations/paystack/callback',webhookUrl:base+'/api/integrations/paystack/webhook',webhookHostRegistered:true,settlementDestinationVerified:true,onboardingAttestedBy:s.userId,onboardingAttestedAt:now,updatedAt:now,updatedBy:s.userId,createdAt:oldPointer?.createdAt||now};
 const pointerSaved=oldPointer?await setRecord('integration_secrets',pointerId,pointer):!!(await db.tx.add('integration_secrets',[pointer]))[0];
 if(!pointerSaved)return bad('Paystack credentials were stored securely but the workspace integration could not be activated. Contact support before retrying.',500);
 await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'WORKSPACE_PAYSTACK_CONFIGURED',entity:'payment_integrations',recordId:merchantAccountId,details:{environment:'production',credentialVersion:credentialId,callbackHost,webhookUrl:pointer.webhookUrl},createdAt:now});
 return res(200,{ok:true,configured:true,environment:'production',credentialVersion:credentialId,callbackUrl:pointer.callbackUrl,webhookUrl:pointer.webhookUrl,message:'Paystack live credentials authenticated and encrypted for this workspace. Register the exact webhook URL in this shop’s Paystack dashboard before selecting Paystack for new orders.'});
}],
'GET /api/integrations/mtn/status':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Managing Director')return bad('Only the Managing Director can manage payment integrations.',403);const ownerId=s.user.ownerId||s.userId,[pointer]=await db.get<any>('integration_secrets',['mtn_workspace_'+ownerId],{consistent:true});const configured=!!pointer&&pointer.status==='active'&&pointer.workspaceId===ownerId&&!!pointer.activeCredentialId,callbackHost=normalizeMtnCallbackHost(pointer?.callbackHost),callbackConfigured=!!configured&&!!callbackHost&&pointer.callbackHostRegistered===true;return res(200,{environment:'production',status:configured?(callbackConfigured?'configured':'callback_host_required'):'not_configured',credentialsConfigured:configured,merchantAccountConnected:configured,callbackConfigured,callbackHost:callbackConfigured?callbackHost:'',callbackUrl:callbackConfigured?'https://'+callbackHost+'/api/integrations/mtn/callback':'',callbackHostRegistered:callbackConfigured,settlementVerification:'Confirm your MTN Collections merchant and settlement destination in the MTN Partner Portal.'})}],
'POST /api/integrations/mtn/configure':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can configure this workspace payment account.',403);
 const b=obj<any>(ctx.body),ownerId=s.user.ownerId||s.userId;
 const subscriptionKey=String(b.subscriptionKey||'').trim(),apiUser=String(b.apiUser||'').trim(),apiKey=String(b.apiKey||'').trim(),merchantBusinessName=String(b.merchantBusinessName||'').trim(),callbackHost=normalizeMtnCallbackHost(b.callbackHost);
 if(subscriptionKey.length<12||subscriptionKey.length>512||apiUser.length<8||apiUser.length>128||apiKey.length<8||apiKey.length>512||merchantBusinessName.length<2||merchantBusinessName.length>160||!callbackHost||b.callbackHostRegistered!==true||b.settlementDestinationVerified!==true)return bad('Enter valid production credentials, a public hostname registered exactly in MTN Partner Portal, and confirm settlement ownership.',400);
 const names=await secrets.listSecretNames();
 if(!names.includes('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'))return bad('Workspace credential encryption is not configured. Contact the platform administrator.',503);
 const masterKey=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY');
 if(masterKey.length<32)return bad('Workspace credential encryption key is invalid. Contact the platform administrator.',503);
 const merchantFingerprint=await mtnMerchantFingerprint(masterKey,subscriptionKey),pointerId='mtn_workspace_'+ownerId,[oldPointer]=await db.get<any>('integration_secrets',[pointerId],{consistent:true});
 if(oldPointer?.merchantFingerprint&&oldPointer.merchantFingerprint!==merchantFingerprint)return bad('This workspace is already bound to a different MTN merchant identity. Changing settlement ownership requires a controlled merchant migration; existing payment records were not changed.',409);
 const claimId='mtn_claim_'+merchantFingerprint,[existingClaim]=await db.get<any>('integration_secrets',[claimId],{consistent:true});
 if(existingClaim&&existingClaim.workspaceId!==ownerId)return bad('These MTN Collections credentials are already assigned to another ShopFlow workspace. Each workspace must use its own merchant account.',409);
 
 let tokenData:any;
 try{
  const auth=await fetch('https://momodeveloper.mtn.com/collection/token/',{method:'POST',headers:{'Ocp-Apim-Subscription-Key':subscriptionKey,'Authorization':'Basic '+btoa(apiUser+':'+apiKey)}});
  if(!auth.ok)return bad('MTN production credentials could not be authenticated. Verify that these credentials belong to this merchant’s Collections product.',502);
  tokenData=obj<any>(await auth.json());
  if(typeof tokenData.access_token!=='string'||!tokenData.access_token)return bad('MTN returned an invalid authentication response.',502);
 }catch{return bad('MTN production credential verification is temporarily unavailable. No credentials were activated.',502)}
 if(!existingClaim){const claim={id:claimId,recordType:'merchant_identity_claim',workspaceId:ownerId,ownerId,merchantFingerprint,createdAt:new Date().toISOString(),createdBy:s.userId};const[claimCreated]=await db.tx.add('integration_secrets',[claim]);if(!claimCreated){const[claimAfterRace]=await db.get<any>('integration_secrets',[claimId],{consistent:true});if(!claimAfterRace||claimAfterRace.workspaceId!==ownerId)return bad('These MTN Collections credentials were claimed by another workspace concurrently. Use the merchant credentials issued for this business.',409);}}
 const merchantAccountId='mtnmerchant_'+ownerId,credentialId='mtncred_'+token(18),encrypted=await encryptWorkspacePaymentCredentials(JSON.stringify({subscriptionKey,apiUser,apiKey}),masterKey,ownerId,credentialId),now=new Date().toISOString();
 const credential={id:credentialId,workspaceId:ownerId,ownerId,merchantAccountId,environment:'production',status:'active',...encrypted,createdAt:now,createdBy:s.userId};
 const[created]=await db.tx.add('integration_secrets',[credential]);
 if(!created)return bad('A new merchant credential version could not be saved. No active payment configuration was changed.',500);
 const pointer={id:pointerId,workspaceId:ownerId,merchantAccountId,merchantFingerprint,provider:'MTN_COLLECTIONS',environment:'production',status:'active',activeCredentialId:credentialId,merchantBusinessName,callbackHost,callbackHostRegistered:true,settlementDestinationVerified:true,onboardingAttestedBy:s.userId,onboardingAttestedAt:now,callbackHostAttestedBy:s.userId,callbackHostAttestedAt:now,updatedAt:now,updatedBy:s.userId,createdAt:oldPointer?.createdAt||now};
 let pointerSaved=false;
 if(oldPointer)pointerSaved=await setRecord('integration_secrets',pointerId,pointer);
 else{const[id]=await db.tx.add('integration_secrets',[pointer]);pointerSaved=!!id}
 if(!pointerSaved)return bad('Credentials were encrypted but the workspace payment account could not be activated. Contact support before retrying.',500);
 await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'WORKSPACE_MTN_COLLECTIONS_CONFIGURED',entity:'payment_integrations',recordId:merchantAccountId,details:{environment:'production',credentialVersion:credentialId,callbackHost,previousCallbackHost:oldPointer?.callbackHost||null},createdAt:now});
 return res(200,{ok:true,status:'configured',environment:'production',merchantAccountConnected:true,credentialVersion:credentialId,callbackHost,callbackUrl:'https://'+callbackHost+'/api/integrations/mtn/callback',message:'MTN production credentials authenticated and encrypted for this workspace. The exact callback hostname must be registered in the merchant’s MTN Partner Portal and the settlement destination verified before accepting live payments.'});
}],
'POST /api/integrations/mtn/callback-host':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can configure this workspace callback host.',403);const b=obj<any>(ctx.body),ownerId=s.user.ownerId||s.userId,callbackHost=normalizeMtnCallbackHost(b.callbackHost);if(!callbackHost||b.callbackHostRegistered!==true)return bad('Enter the exact public hostname registered in MTN Partner Portal and confirm its registration.',400);const pointerId='mtn_workspace_'+ownerId,[pointer]=await db.get<any>('integration_secrets',[pointerId],{consistent:true});if(!pointer||pointer.status!=='active'||pointer.workspaceId!==ownerId||!pointer.activeCredentialId)return bad('Configure this workspace’s MTN Collections merchant credentials before setting its callback host.',409);const now=new Date().toISOString(),updated={...pointer,callbackHost,callbackHostRegistered:true,callbackHostAttestedBy:s.userId,callbackHostAttestedAt:now,updatedAt:now,updatedBy:s.userId};if(!(await setRecord('integration_secrets',pointerId,updated)))return bad('Callback host could not be saved.',500);await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'WORKSPACE_MTN_CALLBACK_HOST_UPDATED',entity:'payment_integrations',recordId:pointer.merchantAccountId,details:{previousCallbackHost:pointer.callbackHost||null,callbackHost},createdAt:now});return res(200,{ok:true,callbackHost,callbackUrl:'https://'+callbackHost+'/api/integrations/mtn/callback',message:'Callback hostname saved. Checkout will use this exact HTTPS host; verify it remains registered in MTN Partner Portal.'})}],
'GET /api/integrations/mtn/legacy-sandbox-status':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can manage payment integrations.',403);
 const names=await secrets.listSecretNames(),[saved]=await db.get<any>('integration_secrets',['mtn_sandbox_credentials'],{consistent:true});
 let fx:any=null,fxError:string|undefined;
 try{const rate=await getMtnSandboxFxRate();fx={rate:rate.rate,source:rate.source,lastUpdatedAt:rate.lastUpdatedAt,lastUpdatedUnix:rate.lastUpdatedUnix,nextUpdateUnix:rate.nextUpdateUnix,fetchedAt:rate.fetchedAt,baseCurrency:'GHS',quoteCurrency:'EUR',status:'available'};}catch{fxError='Live exchange-rate service is unavailable and no sufficiently recent cached rate exists.';}
 return res(200,{environment:'sandbox',sandboxCurrency:'EUR',orderCurrency:'GHS',fxRate:fx,fxError,subscriptionKeyConfigured:names.includes('MTN_MOMO_SUBSCRIPTION_KEY'),credentialsProvisioned:saved?.status==='ready',status:saved?.status==='ready'?'ready':'not_provisioned'});
}],
'POST /api/integrations/mtn/rate/refresh':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can refresh the sandbox exchange rate.',403);
 try{const rate=await getMtnSandboxFxRate(true);return res(200,{ok:true,fxRate:{rate:rate.rate,source:rate.source,lastUpdatedAt:rate.lastUpdatedAt,lastUpdatedUnix:rate.lastUpdatedUnix,nextUpdateUnix:rate.nextUpdateUnix,baseCurrency:'GHS',quoteCurrency:'EUR'}});}catch{return bad('The exchange-rate provider did not return a fresh valid GHS-to-EUR rate. No previous rate was overwritten.',503)}
}],
'POST /api/integrations/mtn/provision':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can provision payment credentials.',403);
 return bad('Shared platform sandbox provisioning is disabled. Configure this workspace’s own MTN Collections merchant account.',410);
 const names=await secrets.listSecretNames();
 if(!names.includes('MTN_MOMO_SUBSCRIPTION_KEY'))return bad('The MTN sandbox subscription key is not configured.',400);
 const subscriptionKey=await secrets.readSecret('MTN_MOMO_SUBSCRIPTION_KEY');
 const [saved]=await db.get<any>('integration_secrets',['mtn_sandbox_credentials'],{consistent:true});
 if(saved?.status==='ready')return res(200,{ok:true,environment:'sandbox',credentialsProvisioned:true,alreadyProvisioned:true});
 try{
  const apiUser=crypto.randomUUID();
  const base='https://sandbox.momodeveloper.mtn.com';
  const createUser=await fetch(base+'/v1_0/apiuser',{method:'POST',headers:{'Content-Type':'application/json','Ocp-Apim-Subscription-Key':subscriptionKey,'X-Reference-Id':apiUser},body:JSON.stringify({providerCallbackHost:undefined})});
  if(!createUser.ok)return bad('MTN sandbox could not create an API user. Check that the subscription key belongs to the Collections product and try again.',502);
  const keyResponse=await fetch(base+'/v1_0/apiuser/'+apiUser+'/apikey',{method:'POST',headers:{'Ocp-Apim-Subscription-Key':subscriptionKey}});
  if(!keyResponse.ok)return bad('MTN created the sandbox API user but did not issue its API key. Retry provisioning; no payment has been initiated.',502);
  const keyData=obj<{apiKey?:string}>(await keyResponse.json().catch(()=>({})));
  if(!keyData.apiKey||keyData.apiKey.length<8)return bad('MTN sandbox returned an unexpected API-key response. No credentials were saved.',502);
  const encrypted=await encryptMtnCredentials(JSON.stringify({apiUser,apiKey:keyData.apiKey}),subscriptionKey);
  const record={id:'mtn_sandbox_credentials',status:'ready',environment:'sandbox',...encrypted,createdAt:new Date().toISOString(),createdBy:s.userId};
  let savedId:string|null=null;
  if(saved?.status==='failed'){
   const ok=await setRecord('integration_secrets','mtn_sandbox_credentials',record);if(ok)savedId='mtn_sandbox_credentials';
  }else{
   const[created]=await db.tx.add('integration_secrets',[record]);savedId=created;
  }
  if(!savedId){
   const[recovered]=await db.get<any>('integration_secrets',['mtn_sandbox_credentials'],{consistent:true});
   if(recovered?.status==='ready')return res(200,{ok:true,environment:'sandbox',credentialsProvisioned:true,alreadyProvisioned:true});
   return bad('Sandbox credentials were generated but could not be saved securely. Retry after checking the integration status.',500);
  }
  await create('audit_logs',{ownerId:s.user.ownerId||s.userId,actorId:s.userId,actorName:s.user.name,action:'MTN_SANDBOX_CREDENTIALS_PROVISIONED',entity:'payment_integrations',recordId:'mtn_sandbox_credentials',createdAt:new Date().toISOString()});
  return res(201,{ok:true,environment:'sandbox',credentialsProvisioned:true,message:'MTN sandbox API credentials were generated and encrypted for backend-only use.'});
 }catch{
  return bad('MTN sandbox provisioning failed due to a network or provider error. Check the subscription key and retry.',502);
 }
}],

'POST /api/onboarding/applications':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<any>(ctx.body),name=String(b.ownerName||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||''),shopName=String(b.shopName||'').trim(),track=String(b.track||''),payoutType=String(b.payoutType||''),accountName=String(b.accountName||'').trim(),accountNumber=String(b.accountNumber||'').replace(/\s+/g,''),network=String(b.network||''),phone=normalizeGhanaPhone(b.phone);
 if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!validPassword(password)||shopName.length<2||!phone||!['formal','individual'].includes(track))return bad('Complete valid owner, email, password, shop and phone details.');
 if(track==='individual'&&payoutType!=='personal_momo'||track==='formal'&&!['corporate_bank','business_momo'].includes(payoutType))return bad('Payout type is not permitted for this seller track.');
 if(['personal_momo','business_momo'].includes(payoutType)&&(!['MTN','Telecel','AT'].includes(network)||!normalizeGhanaPhone(accountNumber)))return bad('Enter a valid supported Mobile Money destination.');
 if(payoutType==='corporate_bank'&&(!/^[0-9A-Za-z-]{6,24}$/.test(accountNumber)||!String(b.bankName||'').trim()))return bad('Enter a valid corporate bank destination.');
 if(accountName.length<2||b.identityConsent!==true||b.termsAccepted!==true)return bad('Beneficiary name and required consent are missing.');
 if(track==='formal'&&(String(b.businessName||'').trim().length<2||String(b.registrationNumber||'').trim().length<3||String(b.businessTin||'').trim().length<3))return bad('Formal businesses must provide registered legal name, registration number and business TIN.');
 const docs=Array.isArray(b.documents)?b.documents:[],need=track==='formal'?['registration_certificate','business_tin_document']:[];for(const k of need)if(!docs.some((d:any)=>d?.kind===k))return bad('Missing required business document: '+k);
 if(docs.some((d:any)=>!['registration_certificate','business_tin_document'].includes(String(d?.kind||''))))return bad('Unsupported onboarding document category.');
 if(docs.length>3)return bad('Too many documents.');
 if((await find<User>('users','email',email)).length)return bad('An account with that email already exists.',409);
 const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(email))),emailHash=Array.from(digest,x=>x.toString(16).padStart(2,'0')).join(''),claimId='registration_email_'+emailHash;
 const workspaceId='ws_'+token(18),userId='md_'+token(18),applicationId='onb_'+token(18),payoutId='payout_'+token(18),now=new Date().toISOString(),names=await secrets.listSecretNames();
 if(!names.includes('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'))return bad('Secure payout storage is not configured.',503);
 const key=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'),encrypted=await encryptWorkspacePaymentCredentials(JSON.stringify({accountNumber}),key,workspaceId,payoutId),paths:string[]=[],savedDocs:any[]=[];
 try{for(const d of docs){const type=String(d.contentType||''),data=String(d.data||''),kind=String(d.kind||''),ext=type==='application/pdf'?'pdf':type==='image/png'?'png':type==='image/jpeg'?'jpg':'';if(!ext||data.length>2600000||!/^[A-Za-z0-9+/]+={0,2}$/.test(data))throw new Error('invalid');const sig=ext==='pdf'?data.startsWith('JVBERi0'):ext==='png'?data.startsWith('iVBORw0KGgo'):data.startsWith('/9j/');if(!sig)throw new Error('signature');const path='onboarding/'+applicationId+'/'+kind+'_'+token(8)+'.'+ext;const[ok]=await storage.write([{path,content:data,contentType:type}]);if(!ok)throw new Error('upload');paths.push(path);savedDocs.push({kind,name:String(d.name||'document').slice(0,100),storagePath:'storage://'+path,contentType:type,uploadedAt:now})}}
 catch{if(paths.length)await storage.delete(paths);return bad('A business document failed secure upload validation. No registration was saved.',400)}
 const account:User={id:userId,name,email,passwordHash:await hash(password),role:'Managing Director',active:true,ownerId:workspaceId,createdAt:now};
 const workspace={id:'workspace_'+workspaceId,recordType:'workspace_registry',workspaceId,ownerId:workspaceId,displayName:shopName,status:'pending_verification',ownerUserId:userId,createdAt:now};
 const settings={id:workspaceId,ownerId:workspaceId,storeName:shopName,city:String(b.town||''),marketplaceEnabled:false,onboardingStatus:'pending_verification',createdAt:now};
 const application={id:applicationId,reference:'SFA-'+applicationId.slice(-10).toUpperCase(),workspaceId,ownerId:workspaceId,ownerUserId:userId,ownerName:name,email,phone:'+'+phone,shopName,category:String(b.category||''),region:String(b.region||''),district:String(b.district||''),town:String(b.town||''),address:String(b.address||''),track,businessName:String(b.businessName||''),registrationNumber:String(b.registrationNumber||''),businessTin:String(b.businessTin||''),documents:savedDocs,identityStatus:'pending_provider_verification',businessStatus:track==='formal'?'pending_manual_review':'not_applicable',payoutVerificationStatus:'pending_hubtel_verification',status:'submitted',submittedAt:now};
 const compliance={id:workspaceId,workspaceId,ownerId:workspaceId,track,complianceTier:'pending_review',limitsStatus:'not_assigned',transactionLimits:{single:null,daily:null,monthly:null,lifetime:null},createdAt:now};
 const payout={id:payoutId,workspaceId,ownerId:workspaceId,payoutType,provider:payoutType==='corporate_bank'?'BANK':network,bankName:String(b.bankName||''),accountName,iv:encrypted.iv,ciphertext:encrypted.ciphertext,keyVersion:encrypted.keyVersion,accountNumberLast4:accountNumber.slice(-4),verificationStatus:'pending_hubtel_verification',isDefault:true,createdAt:now};
 const claim={id:claimId,emailHash,applicationId,workspaceId,createdAt:now},audit={id:'onboarding_'+applicationId,ownerId:workspaceId,actorId:userId,actorName:name,action:'SHOP_REGISTRATION_SUBMITTED',entity:'shop_registration_applications',recordId:applicationId,createdAt:now};
 try{const out=await db.transact([db.tx.add('users',[account]),db.tx.add('marketplace_settings',[workspace,settings]),db.tx.add('shop_registration_applications',[application]),db.tx.add('shop_compliance_profiles',[compliance]),db.tx.add('shop_payout_profiles',[payout]),db.tx.add('registration_email_claims',[claim]),db.tx.add('audit_logs',[audit])]);if(out.some((x:any)=>!x?.[0]))throw new Error('incomplete')}
 catch{await storage.delete(paths);return bad('Workspace registration could not be committed. No activation was confirmed.',409)}
 const csrfToken=token(24),sid=await create('sessions',{userId,csrfToken,expiresAt:Date.now()+TTL});
 return res(201,{application:{reference:application.reference,status:'submitted',track},workspace:{id:workspaceId,name:shopName,status:'pending_verification'},csrfToken,user:{name,email,role:'Managing Director'},message:'Workspace created in restricted onboarding. Identity and payout verification must be completed before marketplace selling and payouts are enabled.'},sid?{'set-cookie':setCookie(sid,TTL/1000)}:{});
}],

'GET /api/auth/session':[async ctx=>{const s=await session(ctx,false);return s?res(200,{authenticated:true,csrfToken:s.csrfToken,user:{name:s.user.name,email:s.user.email,role:s.user.role,avatarUrl:s.user.avatarUrl||''}}):res(200,{authenticated:false})}],
'GET /api/auth/registration-status':[async()=>{const records=await all<User>('users'),accounts=records.filter(isPersistedAccount);return res(200,{registrationAvailable:accounts.length===0,applicationUserRecords:records.length,accountRecords:accounts.length,reason:accounts.length?'An application account already exists.':'No valid application account record exists; initial Managing Director setup is available.'})}],
'POST /api/auth/register':[async ctx=>{if(!unsafe(ctx))return bad('Cross-site request rejected.',403);const b=obj<{name?:string;email?:string;password?:string}>(ctx.body),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');if(name.length<2||name.length>80||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!validPassword(password))return bad('Use a valid name and email, and a password of at least 8 characters with uppercase, lowercase, a number and a special character.');if((await find<User>('users','email',email)).length)return bad('An account with that email already exists.',409);if((await all<User>('users')).some(isPersistedAccount))return bad('An application account already exists. Public registration is closed; use sign-in or the account recovery process.',403);const role='Managing Director',id='initial_managing_director',createdAt=new Date().toISOString(),record={id,name,email,passwordHash:await hash(password),role,active:true,ownerId:id,createdAt};const workspace={id:'workspace_'+id,recordType:'workspace_registry',workspaceId:id,ownerId:id,displayName:name+' workspace',status:'active',ownerUserId:id,createdAt};let created=false;try{const userWrite=db.tx.add('users',[record]),workspaceWrite=db.tx.add('marketplace_settings',[workspace]);const result=await db.transact([userWrite,workspaceWrite]);created=!!result[0]?.[0]&&!!result[1]?.[0]}catch{}if(!created)return bad('Initial Managing Director setup was claimed concurrently or the workspace could not be created atomically. Sign in or contact the existing Managing Director.',409);const csrfToken=token(24),sid=await create('sessions',{userId:id,csrfToken,expiresAt:Date.now()+TTL});if(!sid)return bad('Your Managing Director account was created. Sign in to establish a session.',500);return res(201,{csrfToken,user:{name,email,role}},{'set-cookie':setCookie(sid,TTL/1000)})}],
'POST /api/workspaces/provision':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 if(s.user.role!=='Managing Director')return bad('Only an existing Managing Director can create another Managing Director account.',403);
 const b=obj<any>(ctx.body),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||''),shopName=String(b.shopName||'').trim();
 if(name.length<2||name.length>80||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!validPassword(password)||shopName.length<2||shopName.length>100)return bad('Enter a valid Managing Director name, email, compliant password and new workspace name.',400);
 if((await find<User>('users','email',email)).length)return bad('That email already belongs to an account.',409);
 const workspaceId='ws_'+token(18),userId='md_'+token(18),now=new Date().toISOString();
 const account:User={id:userId,name,email,passwordHash:await hash(password),role:'Managing Director',active:true,ownerId:workspaceId,createdAt:now};
 const workspace={id:'workspace_'+workspaceId,recordType:'workspace_registry',workspaceId,ownerId:workspaceId,displayName:shopName,status:'active',ownerUserId:userId,createdAt:now,createdBy:s.userId};
 const audit={id:'workspace_provision_'+workspaceId,ownerId:s.user.ownerId||s.userId,actorId:s.userId,actorName:s.user.name,action:'WORKSPACE_AND_MANAGING_DIRECTOR_CREATED',entity:'workspaces',recordId:workspaceId,details:{newManagingDirectorId:userId,newManagingDirectorEmail:email,workspaceName:shopName},createdAt:now};
 try{const userWrite=db.tx.add('users',[account]),workspaceWrite=db.tx.add('marketplace_settings',[workspace]),auditWrite=db.tx.add('audit_logs',[audit]);const result=await db.transact([userWrite,workspaceWrite,auditWrite]);if(!result[0]?.[0]||!result[1]?.[0]||!result[2]?.[0])return bad('Workspace and Managing Director provisioning did not commit completely.',409)}catch{return bad('Workspace and Managing Director provisioning could not be committed atomically. No account activation was confirmed.',409)}
 return res(201,{ok:true,workspace:{id:workspaceId,name:shopName,status:'active'},managingDirector:{id:userId,name,email,role:'Managing Director'},message:'A new isolated workspace and its Managing Director account were created. The new Managing Director can sign in with the credentials you supplied.'});
}],
'POST /api/auth/login':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<{email?:string;password?:string}>(ctx.body),email=String(b.email||'').trim().toLowerCase(),p=String(b.password||''),h=headers(ctx.event||ctx),ip=String(h['x-forwarded-for']||ctx.event?.requestContext?.identity?.sourceIp||'').split(',')[0].trim().slice(0,80);
 try{
  const gate=await loginRateLimit(email,ip,false);
  if(gate.blocked)return res(429,{error:'Too many sign-in attempts. Try again after the temporary security hold.',retryAfterSeconds:gate.retryAfterSeconds},{'retry-after':String(gate.retryAfterSeconds)});
  const[u]=await find<User>('users','email',email);
  if(!u||u.active===false||!(await verify(p,u.passwordHash))){
   const failed=await loginRateLimit(email,ip,true);
   if(failed.blocked)return res(429,{error:'Too many sign-in attempts. Try again after the temporary security hold.',retryAfterSeconds:failed.retryAfterSeconds},{'retry-after':String(failed.retryAfterSeconds)});
   return bad('Email or password is incorrect.',401);
  }
  await clearLoginRateLimit(email);
  const csrfToken=token(24),sid=await create('sessions',{userId:u.id,csrfToken,expiresAt:Date.now()+TTL});
  return sid?res(200,{csrfToken,user:{name:u.name,email:u.email,role:u.role}},{'set-cookie':setCookie(sid,TTL/1000)}):bad('Unable to create session.',500);
 }catch(error){console.error('AUTH_RATE_LIMIT_FAILURE '+JSON.stringify({code:String((error as any)?.code||'').slice(0,40)}));return bad('Sign-in protection is temporarily unavailable. Try again shortly.',503);}
}],
'POST /api/auth/logout':[async ctx=>{if(!unsafe(ctx))return bad('Cross-site request rejected.',403);const s=await session(ctx);if(!s)return bad('Session or CSRF token is invalid.',403);await db.delete('sessions',[s.sessionId]);return res(200,{ok:true},{'set-cookie':setCookie('',0)})}],
'POST /api/auth/profile':[async ctx=>{if(!unsafe(ctx))return bad('Cross-site request rejected.',403);const s=await session(ctx);if(!s)return bad('Session or CSRF token is invalid.',403);const b=obj<{name?:string;email?:string;avatarStoragePath?:string}>(ctx.body),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),avatarUrl=String(b.avatarStoragePath??s.user.avatarUrl??'').trim(),ownerId=s.user.ownerId||s.userId;if(name.length<2||name.length>80||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return bad('Enter a valid display name and email address.');if(avatarUrl.startsWith('storage://')&&!storedProfileImagePath(avatarUrl,ownerId,s.userId))return bad('Profile picture must belong to this account and workspace.',403);if(avatarUrl&&!avatarUrl.startsWith('storage://')){if(avatarUrl!==String(s.user.avatarUrl||''))return bad('Upload a profile picture through the account profile form.',400);try{const u=new URL(avatarUrl);if(u.protocol!=='https:'||avatarUrl.length>1000)return bad('Existing profile image URL is invalid.',400)}catch{return bad('Existing profile image URL is invalid.',400)}}const matches=await find<User>('users','email',email);if(matches.some(u=>u.id!==s.userId))return bad('That email is already used by another account.',409);const updated={...s.user,name,email,avatarUrl};if(!(await setRecord('users',s.userId,updated)))return bad('Profile could not be saved.',500);return res(200,{user:{name,email,role:s.user.role,avatarUrl:await resolveProfileImage(avatarUrl,ownerId,s.userId),avatarStoragePath:avatarUrl}})}],
'POST /api/auth/password':[async ctx=>{if(!unsafe(ctx))return bad('Cross-site request rejected.',403);const s=await session(ctx);if(!s)return bad('Session or CSRF token is invalid.',403);const b=obj<{currentPassword?:string;newPassword?:string}>(ctx.body),currentPassword=String(b.currentPassword||''),newPassword=String(b.newPassword||'');if(!validPassword(newPassword))return bad('New password must be at least 8 characters and include uppercase, lowercase, a number and a special character.');if(!(await verify(currentPassword,s.user.passwordHash)))return bad('Current password is incorrect.',401);if(currentPassword===newPassword)return bad('Choose a new password different from your current password.');if(!(await setRecord('users',s.userId,{...s.user,passwordHash:await hash(newPassword)})))return bad('Password could not be updated.',500);for(const item of await all<Session & {id:string}>('sessions'))if(item.userId===s.userId&&item.id!==s.sessionId)await db.delete('sessions',[item.id]);return res(200,{ok:true})}],
'GET /api/shop/marketplace-settings':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can view marketplace configuration.',403);
 const ownerId=s.user.ownerId||s.userId,[saved]=await db.get<any>('marketplace_settings',[ownerId],{consistent:true});
 const identity=resolveShopIdentity(saved,ownerId);
 const settings={...(saved||{}),ownerId,marketplaceEnabled:saved?.marketplaceEnabled===true,storeName:String(saved?.storeName||'').trim(),shopName:identity.shopName,tagline:identity.tagline,city:identity.city,description:identity.description};
 return res(200,{settings,identity});
}],
'POST /api/shop/marketplace-settings':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const s=await session(ctx);if(!s)return bad('Session or CSRF token is invalid.',403);
 if(s.user.role!=='Managing Director')return bad('Only the Managing Director can change marketplace configuration.',403);
 const b=obj<any>(ctx.body),ownerId=s.user.ownerId||s.userId;
 const storeName=String(b.storeName||'').trim(),tagline=String(b.tagline||'').trim(),city=String(b.city||'').trim(),description=String(b.description||'').trim();
 if((storeName.length!==0&&storeName.length<2)||storeName.length>100||tagline.length>140||city.length>100||description.length>500)return bad('Check the shop name, tagline, location and description lengths.',400);
 const [old]=await db.get<any>('marketplace_settings',[ownerId],{consistent:true});
 const settings={...(old||{}),ownerId,marketplaceEnabled:b.marketplaceEnabled===true,storeName,tagline,city,description,updatedAt:new Date().toISOString(),updatedBy:s.userId};
 const legacy=old|| (await db.list<any>('marketplace_settings',{limit:500})).items.find(x=>x.ownerId===ownerId);
 const saved=legacy?await setRecord('marketplace_settings',legacy.id||ownerId,settings):(await db.tx.add('marketplace_settings',[{id:ownerId,...settings}]))[0];
 if(!saved)return bad('Marketplace configuration could not be saved.',500);
 await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'MARKETPLACE_SETTINGS_UPDATED',entity:'marketplace_settings',recordId:ownerId,details:{marketplaceEnabled:settings.marketplaceEnabled,storeName,city},createdAt:new Date().toISOString()});
 const identity=resolveShopIdentity(settings,ownerId);
 return res(200,{settings:{...settings,shopName:identity.shopName},identity,message:settings.marketplaceEnabled?'Your shop is now listed on the ShopFlow marketplace.':'Your shop is hidden from the public marketplace.'});
}],

'POST /api/shop/transactions/detail':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'sales',false);if(denied)return denied;const id=String(obj<any>(ctx.body).id||''),ownerId=s.user.ownerId||s.userId;let sale:any=null,order:any=null,attempt:any=null,receipt:any=null;[sale]=await db.get<any>('sales',[id],{consistent:true});if(sale?.ownerId!==ownerId)sale=null;if(!sale){[order]=await db.get<any>('web_orders',[id],{consistent:true});if(order?.ownerId!==ownerId)order=null;}if(!sale&&!order){[attempt]=await db.get<any>('payment_records',[id],{consistent:true});if(attempt?.ownerId!==ownerId)attempt=null;}if(!sale&&!order&&!attempt)return bad('Transaction not found in this workspace.',404);const saleId=sale?.id||(order?'websale_'+order.id:'');if(saleId)receipt=(await owned<any>('receipts',ownerId)).find(x=>x.saleId===saleId)||null;if(order){const[onlineSale]=await db.get<any>('sales',[saleId],{consistent:true});sale=onlineSale||null;}return res(200,{transaction:clean([sale||order||attempt])[0],order:order?clean([order])[0]:null,paymentAttempt:attempt?clean([attempt])[0]:null,receipt:receipt?clean([receipt])[0]:null});}],
'GET /api/shop/promotions':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Managing Director')return bad('Only the Managing Director can manage promotions.',403);return res(200,{items:clean(await owned<any>('promotions',s.user.ownerId||s.userId))});}],
'POST /api/shop/promotions':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can create promotions.',403);const b=obj<any>(ctx.body),ownerId=s.user.ownerId||s.userId,code=String(b.code||'').trim().toUpperCase(),type=String(b.type||'percentage'),value=num(b.value),startsAt=String(b.startsAt||''),endsAt=String(b.endsAt||'');if(!/^[A-Z0-9_-]{3,24}$/.test(code)||!['percentage','fixed'].includes(type)||!Number.isFinite(value)||value<=0||(type==='percentage'&&value>90)||(type==='fixed'&&value>100000)||startsAt&&!Number.isFinite(Date.parse(startsAt))||endsAt&&!Number.isFinite(Date.parse(endsAt))||startsAt&&endsAt&&Date.parse(endsAt)<=Date.parse(startsAt))return bad('Enter a valid promotion code, discount value and optional date range.',400);if((await owned<any>('promotions',ownerId)).some(x=>String(x.code||'').toUpperCase()===code))return bad('Promotion code already exists in this workspace.',409);const p={id:'promo_'+token(18),ownerId,code,type,value,startsAt,endsAt,active:true,usedCount:0,createdAt:new Date().toISOString(),createdBy:s.userId},created=await create('promotions',p);return created?res(201,{promotion:clean([p])[0]}):bad('Promotion could not be created.',500);}],
'POST /api/shop/promotions/status':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can change promotions.',403);const b=obj<any>(ctx.body),id=String(b.id||''),[p]=await db.get<any>('promotions',[id],{consistent:true});if(!p||p.ownerId!==(s.user.ownerId||s.userId))return bad('Promotion not found.',404);return await setRecord('promotions',id,{...p,active:b.active===true,updatedAt:new Date().toISOString()})?res(200,{ok:true}):bad('Promotion status could not be saved.',500);}],
'GET /api/shop/reviews':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Managing Director')return bad('Only the Managing Director can moderate reviews.',403);return res(200,{items:clean((await owned<any>('product_reviews',s.user.ownerId||s.userId)).sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt))))});}],
'POST /api/shop/reviews/moderate':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can moderate reviews.',403);const b=obj<any>(ctx.body),id=String(b.id||''),status=String(b.status||''),[r]=await db.get<any>('product_reviews',[id],{consistent:true});if(!r||r.ownerId!==(s.user.ownerId||s.userId)||!['Approved','Rejected'].includes(status))return bad('Review or moderation decision is invalid.',400);return await setRecord('product_reviews',id,{...r,status,moderatedBy:s.userId,moderatedAt:new Date().toISOString()})?res(200,{ok:true}):bad('Review moderation failed.',500);}],
'POST /api/storefront/reviews':[async ctx=>{if(!unsafe(ctx))return bad('Cross-site request rejected.',403);const b=obj<any>(ctx.body),orderId=String(b.orderId||''),productId=String(b.productId||''),phone=normalizeGhanaPhone(b.phone),rating=Number(b.rating),title=String(b.title||'').trim(),comment=String(b.comment||'').trim();if(!/^weborder_[A-Za-z0-9_-]{16,80}$/.test(orderId)||!productId||!phone||!Number.isInteger(rating)||rating<1||rating>5||title.length<3||title.length>100||comment.length<10||comment.length>1200)return bad('Enter a delivered order reference, checkout phone, rating, title and review.',400);const[o]=await db.get<any>('web_orders',[orderId],{consistent:true});if(!o||o.status!=='Paid'||normalizeGhanaPhone(o.phone)!==phone||o.fulfillmentStatus!=='Delivered'||!(o.items||[]).some((x:any)=>String(x.productId)===productId))return bad('Only verified customers who received this product can review it.',403);const rid='review_'+orderId+'_'+productId,[old]=await db.get<any>('product_reviews',[rid],{consistent:true});if(old)return bad('A review already exists for this product and order.',409);const review={id:rid,ownerId:o.ownerId,productId,orderId,customerName:o.customer,rating,title,comment,verifiedPurchase:true,status:'Pending',createdAt:new Date().toISOString()},[saved]=await db.tx.add('product_reviews',[review]);return saved?res(201,{ok:true,message:'Verified review submitted for shop moderation.'}):bad('Review could not be saved.',500);}],
'GET /api/storefront/reviews':[async ctx=>{const productId=String(ctx.event?.queryStringParameters?.productId||''),ownerId=String(ctx.event?.queryStringParameters?.storeId||'');if(!productId||!ownerId)return bad('Product and shop references are required.',400);const[p]=await db.get<any>('products',[productId],{consistent:true});if(!p||p.ownerId!==ownerId)return bad('Product not found.',404);const reviews=(await owned<any>('product_reviews',ownerId)).filter(x=>x.productId===productId&&x.status==='Approved').sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt)));return res(200,{items:clean(reviews),average:reviews.length?Math.round(reviews.reduce((n,x)=>n+Number(x.rating),0)/reviews.length*10)/10:0,count:reviews.length});}],
'GET /api/shop/bootstrap':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);const ownerId=s.user.ownerId||s.userId;if(s.user.role==='Managing Director'){const registryId='workspace_'+ownerId,[registered]=await db.get<any>('marketplace_settings',[registryId],{consistent:true});if(!registered){const registry={id:registryId,recordType:'workspace_registry',workspaceId:ownerId,ownerId,displayName:s.user.name+' workspace',status:'active',ownerUserId:s.userId,createdAt:new Date().toISOString(),createdBy:'legacy_workspace_bootstrap'};await db.tx.add('marketplace_settings',[registry]);}}const shopIdentity=await getShopIdentity(ownerId),shopName=shopIdentity.shopName,avatarUrl=await resolveProfileImage(s.user.avatarUrl||'',ownerId,s.userId);const [products,sales,customers,suppliers,purchases,expenses,invoices,stock,team]=await Promise.all([owned<Product>('products',ownerId),owned<Sale>('sales',ownerId),owned<Customer>('customers',ownerId),owned<Supplier>('suppliers',ownerId),owned<Purchase>('purchases',ownerId),owned<Expense>('expenses',ownerId),owned<Invoice>('invoices',ownerId),owned<StockMove>('stock_moves',ownerId),owned<User>('users',ownerId)]);const revenue=sales.reduce((n,x)=>n+x.total,0),cost=sales.reduce((n,x)=>n+x.items.reduce((a,i)=>a+i.qty*(products.find(p=>p.id===i.productId)?.cost||0),0),0),exp=expenses.reduce((n,x)=>n+x.amount,0),purchaseValue=purchases.filter(x=>['Draft','Ordered'].includes(x.status)).reduce((n,x)=>n+x.total,0),receivables=invoices.filter(x=>x.status!=='Paid'&&x.status!=='Cancelled').reduce((n,x)=>n+x.total,0);return res(200,{user:{id:s.user.id,storeId:ownerId,name:s.user.name,email:s.user.email,role:s.user.role,avatarUrl,avatarStoragePath:s.user.avatarUrl||'',shopName},shopIdentity,csrfToken:s.csrfToken,stats:{revenue,orders:sales.length,products:products.length,lowStock:products.filter(p=>p.stock<=p.reorderLevel).length,purchaseValue,expenses:exp,grossProfit:revenue-cost,receivables},data:{products:clean(products),sales:clean(sales.sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,250)),customers:clean(customers),suppliers:clean(suppliers),purchases:clean(purchases),expenses:clean(expenses),invoices:clean(invoices),stock:clean(stock.sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,250)),team:team.filter(x=>s.user.role==='Managing Director'||s.user.role==='General Manager').map(({passwordHash,ownerId,...x})=>x)}})}],
'GET /api/shop/overview':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);const ownerId=s.user.ownerId||s.userId;return res(200,{user:{name:s.user.name,email:s.user.email,role:s.user.role,avatarUrl:await resolveProfileImage(s.user.avatarUrl||'',ownerId,s.userId)}})}],
'GET /api/shop/products':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);return res(200,{items:clean(await owned<Product>('products',s.user.ownerId||s.userId))})}],
'GET /api/shop/sales':[async ctx=>{const s=await session(ctx,false),denied=guard(ctx,s,'sales',false);if(denied)return denied;return res(200,{items:clean(await owned<Sale>('sales',s.user.ownerId||s.userId))})}],
'GET /api/shop/receipts':[async ctx=>{const s=await session(ctx,false),denied=guard(ctx,s,'sales',false);if(denied)return denied;const items=await owned<any>('receipts',s.user.ownerId||s.userId);return res(200,{items:clean(items.sort((a,b)=>String(b.issuedAt||b.createdAt).localeCompare(String(a.issuedAt||a.createdAt))).slice(0,500))})}],
'GET /api/shop/customers':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);return res(200,{items:clean(await owned<Customer>('customers',s.user.ownerId||s.userId))})}],
'POST /api/shop/team':[async ctx=>{const s=await session(ctx);const denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can create team accounts.',403);const b=obj<{name?:string;email?:string;password?:string;role?:string}>(ctx.body),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||''),role=String(b.role||'');if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!validPassword(password)||!roles.includes(role)||role==='Managing Director')return bad('Check name, email, compliant password and allowed role.');if((await find<User>('users','email',email)).length)return bad('That email already has an account.',409);const id=await create('users',{name,email,passwordHash:await hash(password),role,active:true,ownerId:s.user.ownerId||s.userId,createdAt:new Date().toISOString()});return id?res(201,{id,name,email,role}):bad('Team member could not be created.',500)}],
'POST /api/shop/products':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'products');if(denied)return denied;
 const b=obj<any>(ctx.body),name=String(b.name||'').trim(),sku=String(b.sku||'').trim().toUpperCase(),barcode=String(b.barcode||'').trim(),price=num(b.price),cost=num(b.cost||0),stock=num(b.stock),reorderLevel=num(b.reorderLevel??5),imageUrl=String(b.imageUrl||'').trim();
 const imageGallery=Array.isArray(b.imageGallery)?b.imageGallery.map((entry:any)=>typeof entry==='string'?{view:'Additional view',url:String(entry||'').trim()}:{view:String(entry?.view||'Additional view').trim(),url:String(entry?.url||'').trim()}).filter((entry:any)=>entry.url):[];
 const allowedViews=['Front view','Side view','Back view','Top view','Bottom view','Detail view','Packaging','Other view'];
 const textFields=['brand','model','condition','color','size','material','warranty','features','specifications','description'];
 const limits:Record<string,number>={brand:100,model:120,condition:40,color:80,size:120,material:120,warranty:160,features:2000,specifications:4000,description:2000};
 const details:Record<string,string>={};
 for(const key of textFields){details[key]=String(b[key]||'').trim();if(details[key].length>(limits[key]||200))return bad('Product '+key+' exceeds its maximum length.',400)}
 if(name.length<2||name.length>120||!sku||sku.length>40||barcode.length>80||!Number.isFinite(price)||price<=0||!Number.isFinite(cost)||cost<0||!Number.isInteger(stock)||stock<0||stock>100000000||!Number.isInteger(reorderLevel)||reorderLevel<0||reorderLevel>100000000||imageUrl.length>1000||imageGallery.length>8)return bad('Check product details, price, stock, image and specification limits.');
 const ownerId=s.user.ownerId||s.userId;
 for(const image of [{view:'Primary image',url:imageUrl},...imageGallery]){
  if(!image.url)continue;
  if(image.view!=='Primary image'&&!allowedViews.includes(image.view))return bad('Choose a supported product image view.',400);
  if(storedProductImagePath(image.url,ownerId))continue;
  try{if(new URL(image.url).protocol!=='https:')return bad('Product images must use HTTPS or use uploaded ShopFlow images.',400)}catch{return bad('Enter valid HTTPS image URLs or upload an image.',400)}
 }
 const items=await owned<Product>('products',ownerId);
 if(items.some(p=>p.sku===sku||barcode&&p.barcode===barcode))return bad('SKU or barcode already exists.',409);
 const id=crypto.randomUUID(),now=new Date().toISOString(),record={id,name,sku,barcode,category:String(b.category||'General').trim().slice(0,80),price,cost,stock,reorderLevel,imageUrl,imageGallery,...details,updatedAt:now,ownerId};
 try{const operations:any[]=[db.tx.add('products',[record])];if(stock>0)operations.push(db.tx.add('stock_moves',[{id:'opening_'+id,productId:id,productName:name,type:'IN',qty:stock,reason:'Opening stock',actorName:s.user.name,ownerId,createdAt:now}]));await db.transact(operations);return res(201,{id,name,sku,barcode,price,stock})}catch{return bad('Product and opening stock could not be committed together. Refresh inventory and retry.',409)}
}],
'POST /api/shop/products/update':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'products');if(denied)return denied;const b=obj<any>(ctx.body),id=String(b.id||''),ownerId=s.user.ownerId||s.userId;if(!id)return bad('Select an existing product to update.',400);
 const[current]=await db.get<Product>('products',[id],{consistent:true});if(!current||current.ownerId!==ownerId)return bad('Product not found.',404);
 const name=String(b.name??current.name).trim(),sku=String(b.sku??current.sku).trim().toUpperCase(),barcode=String(b.barcode??current.barcode??'').trim(),category=String(b.category??current.category??'General').trim(),price=num(b.price??current.price),cost=num(b.cost??current.cost??0),reorderLevel=num(b.reorderLevel??current.reorderLevel??5),imageUrl=String(b.imageUrl??current.imageUrl??'').trim();
 const imageGallery=Array.isArray(b.imageGallery)?b.imageGallery.map((entry:any)=>typeof entry==='string'?{view:'Additional view',url:String(entry||'').trim()}:{view:String(entry?.view||'Additional view').trim(),url:String(entry?.url||'').trim()}).filter((entry:any)=>entry.url):(Array.isArray(current.imageGallery)?current.imageGallery:[]);
 const allowedViews=['Front view','Side view','Back view','Top view','Bottom view','Detail view','Packaging','Other view'],textFields=['brand','model','condition','color','size','material','warranty','features','specifications','description'];const limits:Record<string,number>={brand:100,model:120,condition:40,color:80,size:120,material:120,warranty:160,features:2000,specifications:4000,description:2000},details:Record<string,string>={};
 for(const key of textFields){details[key]=String(b[key]??(current as any)[key]??'').trim();if(details[key].length>(limits[key]||200))return bad('Product '+key+' exceeds its maximum length.',400)}
 if(name.length<2||name.length>120||!sku||sku.length>40||barcode.length>80||category.length>80||!Number.isFinite(price)||price<=0||!Number.isFinite(cost)||cost<0||!Number.isInteger(reorderLevel)||reorderLevel<0||reorderLevel>100000000||imageUrl.length>1000||imageGallery.length>8)return bad('Check product details, price, image and specification limits.',400);
 const items=await owned<Product>('products',ownerId);if(items.some(p=>p.id!==id&&(p.sku===sku||barcode&&p.barcode===barcode)))return bad('SKU or barcode already exists on another product.',409);
 for(const image of [{view:'Primary image',url:imageUrl},...imageGallery]){if(!image.url)continue;if(image.view!=='Primary image'&&!allowedViews.includes(image.view))return bad('Choose a supported product image view.',400);if(storedProductImagePath(image.url,ownerId))continue;try{if(new URL(image.url).protocol!=='https:')return bad('Product images must use HTTPS or use uploaded ShopFlow images.',400)}catch{return bad('Enter valid HTTPS image URLs or upload an image.',400)}}
 const now=new Date().toISOString(),updated={...current,name,sku,barcode,category,price,cost,reorderLevel,imageUrl,imageGallery,...details,updatedAt:now},condition:any={ownerId};if(current.updatedAt)condition.updatedAt=current.updatedAt;const audit={ownerId,actorId:s.userId,actorName:s.user.name,action:'PRODUCT_UPDATED',entity:'products',recordId:id,before:current,after:updated,createdAt:now};
 try{await db.transact([db.tx.update('products',[{id,record:updated,if:condition}]),db.tx.add('audit_logs',[audit])]);return res(200,{product:updated,message:'Product updated. Stock was preserved; use Stock Management for inventory adjustments.'})}catch{return bad('Product changed concurrently or the update could not be committed. Refresh and retry.',409)}
}],
'POST /api/shop/products/images':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'products');if(denied)return denied;
 const b=obj<any>(ctx.body),id=String(b.productId||''),view=String(b.view||''),imageUrl=String(b.imageUrl||''),ownerId=s.user.ownerId||s.userId;
 const allowedViews=['Front view','Side view','Back view','Top view','Bottom view','Detail view','Packaging','Other view'];
 if(!id||!allowedViews.includes(view)||!storedProductImagePath(imageUrl,ownerId))return bad('Select a product, supported image view and an uploaded image belonging to this workspace.',400);
 const [product]=await db.get<Product>('products',[id]);if(!product||product.ownerId!==ownerId)return bad('Product not found.',404);
 const gallery=Array.isArray(product.imageGallery)?product.imageGallery:[];
 if(gallery.length>=8)return bad('A product can have up to eight additional images.',409);
 const updated={...product,imageGallery:[...gallery,{view,url:imageUrl}],updatedAt:new Date().toISOString()};
 if(!(await setRecord('products',id,updated)))return bad('Product image could not be attached. The uploaded file remains stored but is not linked.',500);
 await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'PRODUCT_GALLERY_IMAGE_ADDED',entity:'products',recordId:id,details:{view},createdAt:new Date().toISOString()});
 return res(200,{product:updated,message:view+' added to product gallery.'});
}],
'GET /api/shop/payment-provider':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);const ownerId=s.user.ownerId||s.userId,payment=await getWorkspaceActivePaymentProvider(ownerId);return res(200,{selectedProvider:payment.activeProvider});}],
'POST /api/shop/pos-payments':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'sales');if(denied)return denied;
 const b=obj<any>(ctx.body),ownerId=s.user.ownerId||s.userId,customer=String(b.customer||'Walk-in customer').trim(),phone=normalizeGhanaPhone(b.phone),email=validPaymentEmail(b.email),network=paystackMobileMoneyCode(b.mobileMoneyProvider),requestId=String(b.requestId||''),items=Array.isArray(b.items)?b.items:[];
 if(!/^[A-Za-z0-9_-]{16,80}$/.test(requestId)||customer.length<2||customer.length>120||!phone||!items.length||items.length>50)return bad('Enter a valid sale reference, customer, Ghana phone number and cart.');
 const payment=await getWorkspaceActivePaymentProvider(ownerId);if(payment.activeProvider==='DISABLED')return bad('This workspace has disabled electronic payments. Choose cash, card, bank transfer or credit.',503);
 if(payment.activeProvider==='PAYSTACK'&&(!email||!network))return bad('Paystack POS requires a valid customer email and Mobile Money network.',400);
 const quantities=new Map<string,number>();for(const item of items){const id=String(item.productId||''),qty=num(item.qty);if(!id||!Number.isInteger(qty)||qty<1||qty>100000)return bad('Each POS item must have a valid product and whole-number quantity.');quantities.set(id,(quantities.get(id)||0)+qty);}
 const products:any[]=[];for(const [productId,qty] of quantities){const [p]=await db.get<Product>('products',[productId]);if(!p||p.ownerId!==ownerId||p.stock<qty)return bad('A POS product is unavailable or has insufficient stock. Refresh the cart and try again.',409);products.push({...p,id:productId,qty});}
 const lines=products.map(p=>({productId:p.id,name:p.name,qty:p.qty,price:Number(p.price)})),total=Math.round(lines.reduce((sum,x)=>sum+x.price*x.qty,0)*100)/100,providerAmount=Math.round(total*100),attemptId='pospay_'+requestId;
 if(!Number.isFinite(total)||total<0.10)return bad('Mobile Money POS payments must be at least GHS 0.10.',400);
 const [existing]=await db.get<any>('payment_records',[attemptId],{consistent:true});if(existing){if(existing.ownerId!==ownerId||existing.requestId!==requestId)return bad('POS payment reference belongs to another workspace.',409);return res(200,{attemptId,status:existing.status,total:existing.total,providerStatus:existing.paystackChargeStatus||existing.mtnStatus,authorizationInstructions:existing.paystackDisplayText||existing.authorizationInstructions||'',message:existing.status==='Paid'?'Payment already confirmed.':existing.status==='Failed'?'This payment attempt failed. Start a new sale attempt only after confirming the original status.':'This payment attempt already exists. Reconcile it instead of initiating another charge.',replayed:true});}
 const now=new Date().toISOString(),attempt:any={id:attemptId,requestId,ownerId,cashierId:s.userId,cashierName:s.user.name,customer,phone,email,smsOptIn:b.smsOptIn===true,paymentNetwork:payment.activeProvider==='PAYSTACK'?network:'mtn',paymentNetworkLabel:payment.activeProvider==='PAYSTACK'?({mtn:'MTN',atl:'AirtelTigo / ATMoney',vod:'Telecel'} as any)[network]:'MTN',items:lines,total,providerAmount,providerCurrency:'GHS',paymentProvider:payment.activeProvider,paymentEnvironment:'production',status:'Initiating',createdAt:now,updatedAt:now,cartSignature:lines.map(x=>x.productId+':'+x.qty).sort().join('|')};
 let merchant:any=null,reference='';
 if(payment.activeProvider==='PAYSTACK'){
  merchant=await loadWorkspacePaystackCredentials(ownerId);if(!merchant)return bad('This workspace has no active Paystack credentials. MTN credentials will not be used as a fallback.',503);
  reference='SF'+crypto.randomUUID().replace(/-/g,'');attempt.paystackReference=reference;attempt.paystackCredentialId=merchant.credentialId;attempt.paystackMerchantAccountId=merchant.merchantAccountId;
  try{await db.transact([db.tx.add('payment_records',[attempt]),db.tx.add('integration_secrets',[{id:'paystack_ref_'+reference,recordType:'payment_reference_index',provider:'PAYSTACK',workspaceId:ownerId,ownerId,channel:'POS',paymentAttemptId:attemptId,reference,credentialId:merchant.credentialId,createdAt:now}])]);}catch{const [raced]=await db.get<any>('payment_records',[attemptId],{consistent:true});if(raced)return res(200,{attemptId,status:raced.status,authorizationInstructions:raced.paystackDisplayText||'',replayed:true});return bad('POS payment attempt could not be safely recorded. No charge was sent.',409);}
  try{
   const charge=await requestPaystackMobileMoneyCharge({workspaceId:ownerId,credentialId:merchant.credentialId,merchantAccountId:merchant.merchantAccountId,email,phone:paystackLocalPhone(phone),network,amount:providerAmount,reference,channel:'POS',entityId:attemptId,customer});
   if(!charge.ok){const status=charge.unknown?'InitiationUnknown':'Failed';await setRecord('payment_records',attemptId,{...attempt,status,paystackHttpStatus:charge.httpStatus,paystackOutcomeUnknown:charge.unknown,failureReason:charge.error,updatedAt:new Date().toISOString()});return res(charge.unknown?503:502,{attemptId,status,error:charge.error,retrySafe:false,message:'Do not submit another charge for this POS attempt. Reconcile the original reference.'});}
   const providerStatus=String(charge.data.status||'').toLowerCase(),displayText=String(charge.data.display_text||charge.payload.message||''),updated={...attempt,status:'Pending',paystackChargeStatus:providerStatus,paystackDisplayText:displayText,paystackAcceptedAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
   await setRecord('payment_records',attemptId,updated);
   if(providerStatus==='success')return await reconcilePaystackPosAttempt(updated);
   return res(202,{attemptId,status:'Pending',providerStatus,authorizationInstructions:displayText,message:providerStatus==='pay_offline'?(displayText||'Approve the Mobile Money request on the customer’s phone.'):'Paystack Mobile Money charge started. Follow the provider instructions to authorize payment.'});
  }catch(error){await setRecord('payment_records',attemptId,{...attempt,status:'InitiationUnknown',paystackOutcomeUnknown:true,updatedAt:new Date().toISOString()}).catch(()=>false);console.error('POS_PAYSTACK_CHARGE_UNKNOWN '+JSON.stringify({attemptId,reference}));return res(503,{attemptId,status:'InitiationUnknown',error:'Paystack response was inconclusive. Reconcile the original payment attempt; do not submit another charge.'});}
 }
 if(payment.activeProvider!=='MTN_COLLECTIONS')return bad('No supported electronic payment provider is selected.',503);
 if(String(b.mobileMoneyProvider||'mtn')!=='mtn')return bad('This workspace uses MTN Collections. Select MTN as the customer network.',400);
 merchant=await loadWorkspaceMtnCredentials(ownerId);if(!merchant)return bad('This workspace has no active MTN Collections production credentials. Paystack credentials will not be used as a fallback.',503);
 const callbackHost=normalizeMtnCallbackHost(merchant.pointer.callbackHost);if(!callbackHost||merchant.pointer.callbackHostRegistered!==true)return bad('The workspace MTN callback hostname is not configured.',503);
 reference=crypto.randomUUID();attempt.mtnReference=reference;attempt.merchantCredentialId=merchant.credentialId;attempt.merchantAccountId=merchant.merchantAccountId;
 try{await db.tx.add('payment_records',[attempt]);}catch{const [raced]=await db.get<any>('payment_records',[attemptId],{consistent:true});if(raced)return res(200,{attemptId,status:raced.status,replayed:true});return bad('POS payment attempt could not be recorded. No MTN request was sent.',409);}
 let providerAccepted=false;
 try{
  const credentials=merchant.credentials,base='https://momodeveloper.mtn.com',auth=await fetch(base+'/collection/token/',{method:'POST',headers:{'Ocp-Apim-Subscription-Key':credentials.subscriptionKey,'Authorization':'Basic '+btoa(credentials.apiUser+':'+credentials.apiKey)}});
  if(!auth.ok)throw new Error('mtn_token_rejected');const tokenData=obj<any>(await auth.json());if(!tokenData.access_token)throw new Error('mtn_token_missing');
  const identity=await getShopIdentity(ownerId),request=await fetch(base+'/collection/v1_0/requesttopay',{method:'POST',headers:{Authorization:'Bearer '+tokenData.access_token,'X-Reference-Id':reference,'X-Target-Environment':'production','Ocp-Apim-Subscription-Key':credentials.subscriptionKey,'Content-Type':'application/json'},body:JSON.stringify({amount:total.toFixed(2),currency:'GHS',externalId:attemptId,payer:{partyIdType:'MSISDN',partyId:phone},payerMessage:mtnSafeNote(identity.shopName+' POS sale '+attemptId),payeeNote:mtnSafeNote(identity.shopName+' POS payment')})});
  if(request.status!==202){const detail=await mtnProviderError(request);throw new Error(detail.message||'mtn_request_rejected');}
  providerAccepted=true;await setRecord('payment_records',attemptId,{...attempt,status:'Pending',mtnAcceptedAt:new Date().toISOString(),updatedAt:new Date().toISOString()});
  return res(202,{attemptId,status:'Pending',message:'MTN Collections accepted the POS payment request. Approve the Mobile Money prompt on the customer’s phone.'});
 }catch(error){await setRecord('payment_records',attemptId,{...attempt,status:providerAccepted?'InitiationUnknown':'Failed',providerOutcomeUnknown:providerAccepted,updatedAt:new Date().toISOString()}).catch(()=>false);return res(providerAccepted?503:502,{attemptId,status:providerAccepted?'InitiationUnknown':'Failed',error:providerAccepted?'MTN accepted the request but the result could not be saved. Reconcile this attempt.':'MTN did not accept the POS payment request. No sale or stock deduction was created.'});}
}],
'POST /api/shop/pos-payments/submit-otp':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'sales');if(denied)return denied;
 const b=obj<any>(ctx.body),attemptId=String(b.attemptId||''),otp=String(b.otp||'').trim(),ownerId=s.user.ownerId||s.userId;
 if(!/^pospay_[A-Za-z0-9_-]{16,80}$/.test(attemptId)||!/^[A-Za-z0-9]{4,12}$/.test(otp))return bad('Enter the authorization code returned by the Mobile Money network.',400);
 const [attempt]=await db.get<any>('payment_records',[attemptId],{consistent:true});
 if(!attempt||attempt.ownerId!==ownerId||attempt.paymentProvider!=='PAYSTACK'||!attempt.paystackReference)return bad('Paystack POS payment attempt not found in this workspace.',404);
 if(String(attempt.paystackChargeStatus||'').toLowerCase()!=='send_otp')return bad('This payment attempt is not waiting for an authorization code. Check its current status.',409);
 const submitted=await submitPaystackMobileMoneyOtp({workspaceId:ownerId,credentialId:String(attempt.paystackCredentialId),merchantAccountId:String(attempt.paystackMerchantAccountId),reference:String(attempt.paystackReference),otp});
 if(!submitted.ok)return bad(submitted.error,submitted.httpStatus>=500?502:400);
 const providerStatus=String(submitted.data.status||'').toLowerCase(),displayText=String(submitted.data.display_text||submitted.payload.message||''),updated={...attempt,status:'Pending',paystackChargeStatus:providerStatus,paystackDisplayText:displayText,otpSubmittedAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
 await setRecord('payment_records',attemptId,updated);
 if(providerStatus==='success')return await reconcilePaystackPosAttempt(updated);
 return res(200,{attemptId,status:'Pending',providerStatus,authorizationInstructions:displayText,message:displayText||'Authorization code submitted. Complete any remaining steps on the customer’s phone, then check payment status.'});
}],
'POST /api/shop/pos-payments/reconcile':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'sales');if(denied)return denied;
 const attemptId=String(obj<any>(ctx.body).attemptId||''),ownerId=s.user.ownerId||s.userId;if(!/^pospay_[A-Za-z0-9_-]{16,80}$/.test(attemptId))return bad('POS payment attempt reference is invalid.',400);
 const [attempt]=await db.get<any>('payment_records',[attemptId],{consistent:true});if(!attempt||attempt.ownerId!==ownerId)return bad('POS payment attempt not found in this workspace.',404);
 if(attempt.paymentProvider==='PAYSTACK')return await reconcilePaystackPosAttempt(attempt);
 if(attempt.paymentProvider!=='MTN_COLLECTIONS'||!attempt.mtnReference)return bad('The original payment provider reference is unavailable.',409);
 if(attempt.status==='Paid')return await finalizePaidPosSale(attempt,attempt.mtnReference,attempt.financialTransactionId||'');
 if(attempt.status==='Failed')return res(200,{attemptId,status:'Failed',message:'MTN did not complete this payment. No sale or stock deduction was created.'});
 const merchant=await loadWorkspaceMtnCredentials(ownerId,String(attempt.merchantCredentialId||''));if(!merchant||merchant.merchantAccountId!==attempt.merchantAccountId)return bad('Original workspace MTN credentials are unavailable. No Paystack credentials will be used.',503);
 try{
  const credentials=merchant.credentials,base='https://momodeveloper.mtn.com',auth=await fetch(base+'/collection/token/',{method:'POST',headers:{'Ocp-Apim-Subscription-Key':credentials.subscriptionKey,'Authorization':'Basic '+btoa(credentials.apiUser+':'+credentials.apiKey)}});
  if(!auth.ok)return bad('MTN status could not be checked. Retry shortly.',502);
  const tokenData=obj<any>(await auth.json());if(!tokenData.access_token)return bad('MTN status could not be checked. Retry shortly.',502);
  const check=await fetch(base+'/collection/v1_0/requesttopay/'+attempt.mtnReference,{headers:{Authorization:'Bearer '+tokenData.access_token,'X-Target-Environment':'production','Ocp-Apim-Subscription-Key':credentials.subscriptionKey}});
  if(!check.ok)return bad('MTN status could not be checked. Keep this payment attempt and retry.',502);
  const result=obj<any>(await check.json()),status=String(result.status||'').toUpperCase();
  if(status==='SUCCESSFUL')return await finalizePaidPosSale(attempt,attempt.mtnReference,String(result.financialTransactionId||''));
  if(['FAILED','REJECTED','TIMEOUT','EXPIRED'].includes(status)){await setRecord('payment_records',attemptId,{...attempt,status:'Failed',mtnStatus:status,failureReason:String(result.reason?.message||status).slice(0,240),updatedAt:new Date().toISOString()});return res(200,{attemptId,status:'Failed',message:'MTN did not complete this payment. No sale or stock deduction was created.'});}
  await setRecord('payment_records',attemptId,{...attempt,status:'Pending',mtnStatus:status,lastStatusCheckedAt:new Date().toISOString()});
  return res(200,{attemptId,status:'Pending',message:'MTN payment is still pending. Approve the Mobile Money prompt and check again.'});
 }catch{return bad('MTN status verification is temporarily unavailable. Retry shortly.',502);}
}],
'POST /api/shop/sales':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'sales');if(denied)return denied;
 const b=obj<any>(ctx.body),customer=String(b.customer||'Walk-in customer').trim(),payment=String(b.payment||'Cash'),ownerId=s.user.ownerId||s.userId,requestId=String(b.requestId||'');
 if(!/^[A-Za-z0-9_-]{16,80}$/.test(requestId))return bad('A valid sale request ID is required.');
 if(!customer||customer.length>120||!['Cash','Mobile Money','Card','Bank transfer','Credit'].includes(payment))return bad('Enter a valid customer name and payment method.');
 const rawItems=Array.isArray(b.items)?b.items:(b.productId?[{productId:b.productId,qty:b.qty}]:[]);
 if(!rawItems.length||rawItems.length>50)return bad('Add between 1 and 50 products to the sale.');
 const quantities=new Map<string,number>();
 for(const item of rawItems){const id=String(item?.productId||'').trim(),quantity=num(item?.qty);if(!id||!Number.isInteger(quantity)||quantity<1||quantity>100000)return bad('Each sale item must have a valid product and a whole-number quantity.');quantities.set(id,(quantities.get(id)||0)+quantity);}
 const normalized=[...quantities.entries()].map(([productId,qty])=>({productId,qty})).sort((a,b)=>a.productId.localeCompare(b.productId));
 const signature=normalized.map(x=>x.productId+':'+x.qty).join('|');
 const saleId='sale_'+requestId,receiptId='receipt_'+requestId,[existing]=await db.get<any>('sales',[saleId],{consistent:true});
 if(existing){
  const previous=(existing.items||[]).map((x:any)=>({productId:String(x.productId),qty:Number(x.qty)})).sort((a:any,b:any)=>a.productId.localeCompare(b.productId)).map((x:any)=>x.productId+':'+x.qty).join('|')||(existing.productId?String(existing.productId)+':'+Number(existing.qty):'');
  if(existing.ownerId!==ownerId||previous!==signature||existing.customer!==customer||existing.payment!==payment)return bad('Sale request ID was already used for different sale details.',409);
  const[receipt]=await db.get<any>('receipts',[receiptId],{consistent:true});
  return res(200,{id:saleId,number:existing.number,total:existing.total,replayed:true,receipt});
 }
 const products:any[]=[];
 for(const item of normalized){const[p]=await db.get<Product>('products',[item.productId]);if(!p||p.ownerId!==ownerId)return bad('One or more selected products could not be found in this workspace.',404);if(!Number.isFinite(p.price)||p.price<0||!Number.isInteger(p.stock)||p.stock<item.qty)return bad('Insufficient stock for '+p.name+'. Available: '+Math.max(0,Number(p.stock)||0)+'.',409);products.push({...p,id:item.productId,qty:item.qty});}
 const now=new Date().toISOString(),number=docNo('RCPT'),identity=await getShopIdentity(ownerId);
 const lines=products.map(p=>({productId:p.id,name:p.name,qty:p.qty,price:p.price,lineTotal:Math.round(p.price*p.qty*100)/100}));
 const total=Math.round(lines.reduce((sum,item)=>sum+item.lineTotal,0)*100)/100;
 const sale={id:saleId,number,requestId,cartSignature:signature,productId:products[0].id,qty:products.reduce((sum,p)=>sum+p.qty,0),items:lines,total,payment,customer,createdAt:now,ownerId,agentName:s.user.name};
 const receipt={id:receiptId,ownerId,saleId,receiptNumber:number,number,storeName:identity.shopName,tagline:identity.tagline,city:identity.city,customer,paymentMethod:payment,paymentStatus:payment==='Credit'?'On account':'Received',items:lines.map(item=>({productId:item.productId,name:item.name,qty:item.qty,unitPrice:item.price,lineTotal:item.lineTotal})),subtotal:total,discount:0,tax:0,total,currency:'GHS',cashierName:s.user.name,issuedAt:now,createdAt:now};
 const operations:any[]=[db.tx.add('sales',[sale]),db.tx.add('receipts',[receipt])];
 for(const p of products){operations.push(db.tx.update('products',[{id:p.id,record:{...p,stock:p.stock-p.qty,updatedAt:now},if:{stock:p.stock}}]));operations.push(db.tx.add('stock_moves',[{id:'sale_move_'+requestId+'_'+p.id,productId:p.id,productName:p.name,type:'OUT',qty:p.qty,reason:'Sale '+number,actorName:s.user.name,ownerId,createdAt:now}]));}
 try{await db.transact(operations);}
 catch(error){const[recovered]=await db.get<any>('sales',[saleId],{consistent:true}).catch(()=>[null]);if(recovered&&recovered.ownerId===ownerId&&recovered.requestId===requestId){const[recoveredReceipt]=await db.get<any>('receipts',[receiptId],{consistent:true}).catch(()=>[null]);return res(200,{id:saleId,number:recovered.number,total:recovered.total,replayed:true,receipt:recoveredReceipt});}console.error('POS_SALE_COMMIT_FAILED '+JSON.stringify({requestId,itemCount:products.length}));return bad('The sale could not be confirmed. Inventory and receipt were not committed. Retry using the same sale attempt; do not create a new sale.',409);}
 try{const cs=await owned<Customer>('customers',ownerId),c=cs.find(x=>x.name.toLowerCase()===customer.toLowerCase());if(c)await setRecord('customers',c.id,{...c,visits:c.visits+1,lifetimeValue:(c.lifetimeValue||0)+total});else await create('customers',{name:customer,phone:'',visits:1,lifetimeValue:total,ownerId});await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'SALE_CREATED',entity:'sales',recordId:saleId,receiptNumber:number,details:{itemCount:lines.length,total},createdAt:now});}
 catch(error){console.error('POS_SALE_POST_COMMIT_HOUSEKEEPING_FAILED '+JSON.stringify({requestId,itemCount:lines.length}));}
 return res(201,{id:saleId,number,total,stockRemaining:products.map(p=>({productId:p.id,stock:p.stock-p.qty})),receipt});
}],
'POST /api/shop/stock':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'stock');if(denied)return denied;const b=obj<any>(ctx.body),id=String(b.productId||''),type=String(b.type||'IN'),qty=num(b.qty),reason=String(b.reason||'').trim(),ownerId=s.user.ownerId||s.userId;const[p]=await db.get<Product>('products',[id]);if(!p||p.ownerId!==ownerId)return bad('Product not found.',404);if(!['IN','OUT','SET'].includes(type)||!Number.isInteger(qty)||qty<0||!reason||reason.length>240)return bad('Enter valid movement, quantity and reason.');const nextStock=type==='IN'?p.stock+qty:type==='OUT'?p.stock-qty:qty;if(!Number.isSafeInteger(nextStock)||nextStock<0)return bad('Stock cannot become negative or exceed the supported quantity.',409);const now=new Date().toISOString(),mid='stockmove_'+token(18);try{const update=db.tx.update('products',[{id,record:{...p,stock:nextStock,updatedAt:now},if:{stock:p.stock}}]);const movement=db.tx.add('stock_moves',[{id:mid,productId:id,productName:p.name,type,qty:type==='SET'?Math.abs(nextStock-p.stock):qty,reason,actorName:s.user.name,ownerId,createdAt:now}]);await db.transact([update,movement]);return res(201,{id:mid,stock:nextStock})}catch{return bad('Stock changed concurrently or the adjustment could not be committed. Refresh inventory and retry.',409)}}],
'POST /api/shop/suppliers':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'suppliers');if(denied)return denied;const b=obj<any>(ctx.body),name=String(b.name||'').trim();if(name.length<2)return bad('Supplier name is required.');const id=await create('suppliers',{name,contact:String(b.contact||''),email:String(b.email||''),phone:String(b.phone||''),address:String(b.address||''),taxId:String(b.taxId||''),ownerId:s.user.ownerId||s.userId,createdAt:new Date().toISOString()});return id?res(201,{id,name}):bad('Supplier could not be saved.',500)}],
'POST /api/shop/purchases':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'purchases');if(denied)return denied;const b=obj<any>(ctx.body),qty=num(b.qty),unitCost=num(b.unitCost),ownerId=s.user.ownerId||s.userId,productModel=String(b.productModel||'').trim(),brand=String(b.brand||'').trim(),specifications=String(b.specifications||'').trim();if(!Number.isInteger(qty)||qty<1||qty>1000000||!Number.isFinite(unitCost)||unitCost<0||unitCost>1000000000||!b.supplierId||!b.productId||productModel.length>120||brand.length>100||specifications.length>4000)return bad('Select supplier and product and enter valid quantity, cost and optional specification details.');const[supRaw]=await db.get<Supplier>('suppliers',[String(b.supplierId)]),[productRaw]=await db.get<Product>('products',[String(b.productId)]),sup=supRaw?{...supRaw,id:String(b.supplierId)}:null,p=productRaw?{...productRaw,id:String(b.productId)}:null;if(!sup||sup.ownerId!==ownerId||!p||p.ownerId!==ownerId)return bad('Supplier or product not found.',404);const number=docNo('PO'),record={number,supplierId:sup.id,supplierName:sup.name,productId:p.id,productName:p.name,productModel:productModel||p.model||'',brand:brand||p.brand||'',specifications:specifications||p.specifications||'',qty,unitCost,total:Math.round(qty*unitCost*100)/100,status:'Draft',expectedDate:String(b.expectedDate||''),ownerId,createdAt:new Date().toISOString()};const id=await create('purchases',record);return id?res(201,{id,number}):bad('Purchase order failed.',500)}],
'POST /api/shop/expenses':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'expenses');if(denied)return denied;const b=obj<any>(ctx.body),amount=num(b.amount),description=String(b.description||'').trim();if(!description||!Number.isFinite(amount)||amount<=0)return bad('Enter an expense description and positive amount.');const id=await create('expenses',{description,category:String(b.category||'Other'),amount,date:String(b.date||new Date().toISOString().slice(0,10)),payment:String(b.payment||'Cash'),actorName:s.user.name,ownerId:s.user.ownerId||s.userId,createdAt:new Date().toISOString()});return id?res(201,{id}):bad('Expense could not be saved.',500)}],
'POST /api/shop/invoices':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'invoices');if(denied)return denied;const b=obj<any>(ctx.body),qty=num(b.qty),unitPrice=num(b.unitPrice),customer=String(b.customer||'').trim(),description=String(b.description||'').trim();if(!customer||!description||!Number.isInteger(qty)||qty<1||!Number.isFinite(unitPrice)||unitPrice<=0)return bad('Enter customer, description, quantity and positive price.');const number=docNo('INV'),record={number,customer,customerPhone:String(b.customerPhone||''),description,qty,unitPrice,total:Math.round(qty*unitPrice*100)/100,status:'Issued',dueDate:String(b.dueDate||''),ownerId:s.user.ownerId||s.userId,createdAt:new Date().toISOString()};const id=await create('invoices',record);return id?res(201,{id,number,total:record.total}):bad('Invoice could not be created.',500)}],
'POST /api/shop/status':[async ctx=>{const s=await session(ctx),b=obj<{id?:string;status?:string;entity?:string}>(ctx.body),entity=String(b.entity||''),key=entity==='purchases'?'purchases':entity==='invoices'?'invoices':'team',denied=guard(ctx,s,key);if(denied)return denied;const id=String(b.id||''),status=String(b.status||''),ownerId=s.user.ownerId||s.userId;if(entity==='team'){if(s.user.role!=='Managing Director')return bad('Only Managing Director can change team access.',403);const[u]=await db.get<User>('users',[id]);if(!u||u.ownerId!==ownerId||u.role==='Managing Director'||!['Active','Disabled'].includes(status))return bad('Team record or status invalid.',400);return await setRecord('users',id,{...u,active:status==='Active'})?res(200,{ok:true}):bad('Update failed.',500)}if(entity==='invoices'){const[i]=await db.get<Invoice>('invoices',[id]);if(!i||i.ownerId!==ownerId||!['Paid','Cancelled'].includes(status))return bad('Invoice status invalid.',400);return await setRecord('invoices',id,{...i,status})?res(200,{ok:true}):bad('Update failed.',500)}if(entity==='purchases'){const[p]=await db.get<Purchase>('purchases',[id]);if(!p||p.ownerId!==ownerId)return bad('Purchase order not found.',404);if(status==='Ordered'&&p.status==='Draft'){const[ok]=await db.tx.update('purchases',[{id,record:{...p,status,updatedAt:new Date().toISOString()},if:{status:'Draft'}}]);return ok?res(200,{ok:true}):bad('Purchase order changed concurrently. Refresh and retry.',409)}if(status==='Received'&&p.status==='Ordered'){const[product]=await db.get<Product>('products',[p.productId]);if(!product||product.ownerId!==ownerId)return bad('Product not found.',404);const now=new Date().toISOString(),moveId='poreceive_'+id;try{const productUpdate=db.tx.update('products',[{id:String(p.productId),record:{...product,stock:product.stock+p.qty,cost:p.unitCost,updatedAt:now},if:{stock:product.stock}}]);const purchaseUpdate=db.tx.update('purchases',[{id,record:{...p,status:'Received',receivedAt:now,receivedBy:s.userId},if:{status:'Ordered'}}]);const movement=db.tx.add('stock_moves',[{id:moveId,productId:p.productId,productName:p.productName,type:'IN',qty:p.qty,reason:'Received '+p.number,actorName:s.user.name,ownerId,createdAt:now}]);await db.transact([productUpdate,purchaseUpdate,movement]);await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'PURCHASE_RECEIVED',entity:'purchases',recordId:id,details:{productId:p.productId,quantity:p.qty},createdAt:now});return res(200,{ok:true,status:'Received'})}catch{return bad('Purchase receipt could not be committed atomically. Refresh the purchase order and inventory before retrying.',409)}}return bad('Invalid purchase-order transition.',409)}return bad('Unknown status entity.') }],
'POST /api/shop/team/manage':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can manage team accounts.',403);const b=obj<any>(ctx.body),id=String(b.id||''),role=String(b.role||''),active=Boolean(b.active),ownerId=s.user.ownerId||s.userId;const[u]=await db.get<User>('users',[id]);if(!u||u.ownerId!==ownerId||u.role==='Managing Director'||!roles.includes(role)||role==='Managing Director')return bad('Team record or role is invalid.',400);if(!(await setRecord('users',id,{...u,role,active})))return bad('Team account could not be updated.',500);await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'TEAM_ACCOUNT_UPDATED',entity:'users',recordId:id,details:{role,active},createdAt:new Date().toISOString()});return res(200,{ok:true})}],
'POST /api/auth/reset/issue':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can issue a password reset token.',403);const b=obj<{email?:string}>(ctx.body),email=String(b.email||'').trim().toLowerCase(),[u]=await find<User>('users','email',email),ownerId=s.user.ownerId||s.userId;if(!u||u.ownerId!==ownerId||u.role==='Managing Director')return bad('Team account not found.',404);const raw=token(24),createdAt=Date.now(),record={userId:u.id,email:u.email,tokenHash:await hash(raw),ownerId,issuedBy:s.userId,createdAt,expiresAt:createdAt+30*60*1000,used:false};const stored=await create('password_resets',record);if(!stored)return bad('Reset token could not be issued.',500);await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'PASSWORD_RESET_TOKEN_ISSUED',entity:'users',recordId:u.id,createdAt:new Date().toISOString()});return res(201,{ok:true,email:u.email,token:raw,expiresInMinutes:30,message:'Share this one-time token with the verified account holder through a separate trusted channel. It is shown only once.'})}],
'POST /api/auth/reset/complete':[async ctx=>{if(!unsafe(ctx))return bad('Cross-site request rejected.',403);const b=obj<{email?:string;token?:string;newPassword?:string}>(ctx.body),email=String(b.email||'').trim().toLowerCase(),raw=String(b.token||''),newPassword=String(b.newPassword||'');if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||raw.length<20||!validPassword(newPassword))return bad('Enter a valid email, reset token and compliant new password.');const[u]=await find<User>('users','email',email);if(!u)return bad('Reset token is invalid or expired.',400);const resets=await find<any>('password_resets','email',email);let reset:any=null;for(const candidate of resets){if(!candidate.used&&candidate.expiresAt>Date.now()&&await verify(raw,candidate.tokenHash)){reset=candidate;break}}if(!reset)return bad('Reset token is invalid or expired.',400);const{ id:resetId,...resetRecord}=reset,{ id:userId,...userRecord}=u;try{const consume=db.tx.update('password_resets',[{id:resetId,record:{...resetRecord,used:true,usedAt:Date.now()},if:{used:false}}]);const updateUser=db.tx.update('users',[{id:userId,record:{...userRecord,passwordHash:await hash(newPassword)}}]);await db.transact([consume,updateUser])}catch{return bad('Reset token is invalid, expired or already used.',400)}for(const item of await all<Session & {id:string}>('sessions'))if(item.userId===userId)await db.delete('sessions',[item.id]);await create('audit_logs',{ownerId:u.ownerId,actorId:userId,actorName:u.name,action:'PASSWORD_RESET_COMPLETED',entity:'users',recordId:userId,createdAt:new Date().toISOString()});return res(200,{ok:true,message:'Password reset. You can now sign in.'})}],
'GET /api/shop/change-requests':[async ctx=>{const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);const ownerId=s.user.ownerId||s.userId,items=await owned<any>('change_requests',ownerId);return res(200,{items:items.filter(x=>s.user.role==='Managing Director'||x.requesterId===s.userId).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).slice(0,250)})}],
'POST /api/shop/change-requests':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'overview');if(denied)return denied;const b=obj<any>(ctx.body),entity=String(b.entity||''),action=String(b.action||''),recordId=String(b.recordId||''),reason=String(b.reason||'').trim(),direct=Boolean(b.direct),ownerId=s.user.ownerId||s.userId;const tableMap:Record<string,string>={products:'products',suppliers:'suppliers',purchases:'purchases',expenses:'expenses',invoices:'invoices',customers:'customers'};const fieldMap:Record<string,string[]>={products:['name','sku','barcode','category','price','cost','stock','reorderLevel'],suppliers:['name','contact','email','phone','address','taxId'],purchases:['status','expectedDate','qty','unitCost'],expenses:['description','category','amount','date','payment'],invoices:['customer','customerPhone','description','qty','unitPrice','status','dueDate'],customers:['name','phone']};const table=tableMap[entity];if(!table||!['update','delete'].includes(action)||!recordId)return bad('Unsupported record or action.');if(s.user.role==='Managing Director'&&!direct&&reason.length<15)return bad('Provide a meaningful reason of at least 15 characters.',400);if(s.user.role!=='Managing Director'&&(direct||reason.length<15))return bad('Provide a meaningful reason of at least 15 characters and request approval.',403);const[current]=await db.get<any>(table,[recordId]);if(!current||current.ownerId!==ownerId)return bad('Record not found.',404);let proposed:Record<string,any>={};if(action==='update'){if(!b.proposedData||typeof b.proposedData!=='object'||Array.isArray(b.proposedData))return bad('Provide the proposed field changes.');for(const k of fieldMap[entity])if(Object.prototype.hasOwnProperty.call(b.proposedData,k))proposed[k]=b.proposedData[k];if(!Object.keys(proposed).length)return bad('No permitted fields were supplied.')}if(s.user.role==='Managing Director'&&direct){if(action==='delete'){const[ok]=await db.tx.delete(table,[recordId]);if(!ok)return bad('Record could not be deleted.',409)}else if(!(await setRecord(table,recordId,{...current,...proposed,updatedAt:new Date().toISOString()})))return bad('Record could not be updated.',409);await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'DIRECT_'+action.toUpperCase(),entity,recordId,reason:reason||'Managing Director direct action',before:current,after:action==='update'?{...current,...proposed}:null,createdAt:new Date().toISOString()});return res(200,{ok:true,direct:true})}const request={ownerId,requesterId:s.userId,requesterName:s.user.name,entity,table,recordId,action,reason,proposedData:proposed,before:current,status:'Pending',createdAt:new Date().toISOString()};const id=await create('change_requests',request);if(!id)return bad('Change request could not be saved.',500);await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'CHANGE_REQUEST_SUBMITTED',entity,recordId,requestId:id,reason,createdAt:new Date().toISOString()});return res(201,{id,status:'Pending'})}],
'POST /api/shop/change-requests/decision':[async ctx=>{const s=await session(ctx),denied=guard(ctx,s,'overview');if(denied)return denied;if(s.user.role!=='Managing Director')return bad('Only the Managing Director can decide change requests.',403);const b=obj<any>(ctx.body),id=String(b.id||''),decision=String(b.decision||''),ownerId=s.user.ownerId||s.userId;if(!['Approved','Rejected'].includes(decision))return bad('Decision must be Approved or Rejected.');const[r]=await db.get<any>('change_requests',[id]);if(!r||r.ownerId!==ownerId||r.status!=='Pending')return bad('Pending request not found.',404);if(r.requesterId===s.userId)return bad('You cannot approve or reject your own request.',403);const before=r.before;if(decision==='Approved'){const[current]=await db.get<any>(r.table,[r.recordId]);if(!current||current.ownerId!==ownerId||JSON.stringify(current)!==JSON.stringify(before))return bad('Record changed since the request was submitted. Reject this request and ask for a fresh one.',409);if(r.action==='delete'){const[ok]=await db.tx.delete(r.table,[r.recordId]);if(!ok)return bad('Record could not be deleted.',409)}else if(!(await setRecord(r.table,r.recordId,{...current,...r.proposedData,updatedAt:new Date().toISOString()})))return bad('Record could not be updated.',409)}const now=new Date().toISOString();if(!(await setRecord('change_requests',id,{...r,status:decision,decidedBy:s.userId,decidedByName:s.user.name,decidedAt:now})))return bad('Decision could not be saved.',500);await create('audit_logs',{ownerId,actorId:s.userId,actorName:s.user.name,action:'CHANGE_REQUEST_'+decision.toUpperCase(),entity:r.entity,recordId:r.recordId,requestId:id,reason:r.reason,before,after:decision==='Approved'&&r.action==='update'?{...before,...r.proposedData}:null,createdAt:now});return res(200,{ok:true,status:decision})}],

'GET /api/auth/registration-status':[async()=>{
 const users=await all<User>('users');
 const accounts=users.filter(isPersistedAccount);
 const platformAdmin=accounts.some(u=>u.role==='Super Admin'||u.id==='initial_managing_director');
 return res(200,{registrationAvailable:accounts.length===0,platformAdminConfigured:platformAdmin,accountRecords:accounts.length,reason:platformAdmin?'The platform administrator account is already configured.':'The first account will be the ShopFlow platform Super Admin.'});
}],
'POST /api/auth/register':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<any>(ctx.body),name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
 if(name.length<2||name.length>80||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!validPassword(password))return bad('Enter a valid name and email, and a password with uppercase, lowercase, a number and a special character.');
 const users=await all<User>('users');
 if(users.some(isPersistedAccount))return bad('The initial Super Admin account already exists. Sign in or use account recovery.',403);
 if(users.some(u=>String(u.email||'').toLowerCase()===email))return bad('An account with that email already exists.',409);
 const now=new Date().toISOString(),id='platform_super_admin';
 const record:User={id,name,email,passwordHash:await hash(password),role:'Super Admin',active:true,ownerId:'shopflow_platform',createdAt:now};
 const audit={id:'platform_bootstrap_'+token(12),ownerId:'shopflow_platform',actorId:id,actorName:name,action:'INITIAL_SUPER_ADMIN_CREATED',entity:'platform_accounts',recordId:id,createdAt:now};
 try{
  const out=await db.transact([db.tx.add('users',[record]),db.tx.add('audit_logs',[audit])]);
  if(!out[0]?.[0]||!out[1]?.[0])return bad('Initial platform administrator setup could not be committed. Retry or contact support.',409);
 }catch{return bad('Initial platform administrator setup could not be committed. No successful account creation was confirmed.',409)}
 const csrfToken=token(24),sid=await create('sessions',{userId:id,csrfToken,expiresAt:Date.now()+TTL});
 return sid?res(201,{csrfToken,user:{id,name,email,role:'Super Admin'},message:'ShopFlow platform administrator created.'},{'set-cookie':setCookie(sid,TTL/1000)}):bad('The Super Admin account was created, but a session could not be established. Sign in.',500);
}],
'POST /api/workspaces/provision':[async ctx=>{
 const s=await session(ctx),denied=guard(ctx,s,'team');if(denied)return denied;
 return bad('Managing Director accounts can only be created after a Super Admin approves a shop registration application.',403);
}],
'POST /api/onboarding/applications':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<any>(ctx.body),name=String(b.ownerName||'').trim(),email=String(b.email||'').trim().toLowerCase(),shopName=String(b.shopName||'').trim(),track=String(b.track||''),payoutType=String(b.payoutType||''),accountName=String(b.accountName||'').trim(),accountNumber=String(b.accountNumber||'').replace(/\s+/g,''),network=String(b.network||''),phone=normalizeGhanaPhone(b.phone),registrationToken=String(b.registrationToken||'').trim();
 if(!/^[a-f0-9]{64}$/i.test(registrationToken))return bad('A valid ShopFlow registration link is required. Contact the platform administrator.',403);
 const tokenHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(registrationToken))),x=>x.toString(16).padStart(2,'0')).join('');
 const links=await find<any>('shop_registration_links','tokenHash',tokenHash),link=links[0];
 if(!link||link.revokedAt||link.usedAt||new Date(link.expiresAt).getTime()<Date.now())return bad('This registration link is invalid, expired or already used. Request a new link from the platform administrator.',403);
 if(name.length<2||name.length>80||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||shopName.length<2||shopName.length>100||!phone||!['formal','individual'].includes(track))return bad('Complete valid owner, email, Ghana phone, shop and seller-type details.');
 if(track==='individual'&&payoutType!=='personal_momo'||track==='formal'&&!['corporate_bank','business_momo'].includes(payoutType))return bad('The selected payout method is not permitted for this seller type.');
 if(['personal_momo','business_momo'].includes(payoutType)&&(!['MTN','Telecel','AT'].includes(network)||!normalizeGhanaPhone(accountNumber)))return bad('Enter a valid supported Mobile Money destination.');
 if(payoutType==='corporate_bank'&&(!/^[0-9A-Za-z-]{6,24}$/.test(accountNumber)||!String(b.bankName||'').trim()))return bad('Enter a valid corporate bank destination.');
 if(accountName.length<2||b.identityConsent!==true||b.termsAccepted!==true)return bad('Beneficiary name and required consent are missing.');
 if(track==='formal'&&(String(b.businessName||'').trim().length<2||String(b.registrationNumber||'').trim().length<3||String(b.businessTin||'').trim().length<3))return bad('Formal businesses must provide registered legal name, registration number and business TIN.');
 const ghanaCard=String(b.ghanaCardNumber||'').trim().toUpperCase();
 if(track==='individual'&&!/^GHA-[0-9]{9}-[0-9]$/.test(ghanaCard))return bad('Enter a valid Ghana Card number in the format GHA-XXXXXXXXX-X.');
 const docs=Array.isArray(b.documents)?b.documents:[],need=track==='formal'?['registration_certificate','business_tin_document']:[];
 for(const kind of need)if(!docs.some((d:any)=>d?.kind===kind))return bad('Missing required business document: '+kind);
 if(docs.some((d:any)=>!['registration_certificate','business_tin_document'].includes(String(d?.kind||'')))||docs.length>2)return bad('Unsupported onboarding document category.');
 if((await find<User>('users','email',email)).length)return bad('An account with that email already exists.',409);
 if((await find<any>('shop_registration_applications','email',email)).some(x=>['submitted','under_review','approved'].includes(x.status)))return bad('A registration application already exists for this email.',409);
 const workspaceId='ws_'+token(18),applicationId='onb_'+token(18),payoutId='payout_'+token(18),identityId='identity_'+token(18),now=new Date().toISOString();
 const names=await secrets.listSecretNames();
 if(!names.includes('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY'))return bad('Secure payout and identity storage is not configured.',503);
 const key=await secrets.readSecret('SHOPFLOW_WORKSPACE_PAYMENT_ENCRYPTION_KEY');
 const encryptedPayout=await encryptWorkspacePaymentCredentials(JSON.stringify({accountNumber}),key,workspaceId,payoutId);
 const encryptedIdentity=track==='individual'?await encryptWorkspacePaymentCredentials(JSON.stringify({ghanaCardNumber:ghanaCard}),key,workspaceId,identityId):null;
 const paths:string[]=[],savedDocs:any[]=[];
 try{
  for(const d of docs){
   const type=String(d.contentType||''),data=String(d.data||''),kind=String(d.kind||''),ext=type==='application/pdf'?'pdf':type==='image/png'?'png':type==='image/jpeg'?'jpg':'';
   if(!ext||data.length>2600000||!/^[A-Za-z0-9+/]+={0,2}$/.test(data))throw new Error('invalid_document');
   const signature=ext==='pdf'?data.startsWith('JVBERi0'):ext==='png'?data.startsWith('iVBORw0KGgo'):data.startsWith('/9j/');
   if(!signature)throw new Error('invalid_signature');
   const path='onboarding/'+applicationId+'/'+kind+'_'+token(8)+'.'+ext;
   const[ok]=await storage.write([{path,content:data,contentType:type}]);
   if(!ok)throw new Error('upload_failed');
   paths.push(path);savedDocs.push({kind,name:String(d.name||'document').slice(0,100),storagePath:'storage://'+path,contentType:type,uploadedAt:now});
  }
 }catch{if(paths.length)await storage.delete(paths);return bad('A business document failed secure upload validation. No application was saved.',400)}
 const reference='SFA-'+applicationId.slice(-10).toUpperCase();
 const application={id:applicationId,reference,workspaceId,ownerId:workspaceId,registrationLinkId:link.id,ownerName:name,email,phone:'+'+phone,shopName,category:String(b.category||''),region:String(b.region||''),district:String(b.district||''),town:String(b.town||''),address:String(b.address||''),track,businessName:String(b.businessName||''),registrationNumber:String(b.registrationNumber||''),businessTin:String(b.businessTin||''),documents:savedDocs,identityStatus:'pending_provider_verification',businessStatus:track==='formal'?'pending_manual_review':'not_applicable',payoutVerificationStatus:'pending_hubtel_verification',status:'submitted',submittedAt:now};
 const compliance={id:workspaceId,workspaceId,ownerId:workspaceId,track,complianceTier:'pending_review',limitsStatus:'not_assigned',transactionLimits:{single:null,daily:null,monthly:null,lifetime:null},identityVerification:track==='individual'?{id:identityId,iv:encryptedIdentity.iv,ciphertext:encryptedIdentity.ciphertext,keyVersion:encryptedIdentity.keyVersion,ghanaCardLast4:ghanaCard.slice(-4),status:'pending_provider_verification'}:{status:'not_applicable'},createdAt:now};
 const payout={id:payoutId,workspaceId,ownerId:workspaceId,payoutType,provider:payoutType==='corporate_bank'?'BANK':network,bankName:String(b.bankName||''),accountName,iv:encryptedPayout.iv,ciphertext:encryptedPayout.ciphertext,keyVersion:encryptedPayout.keyVersion,accountNumberLast4:accountNumber.slice(-4),verificationStatus:'pending_hubtel_verification',isDefault:true,createdAt:now};
 const audit={id:'onboarding_'+applicationId,ownerId:'shopflow_platform',actorId:'public_applicant',actorName:name,action:'SHOP_REGISTRATION_APPLICATION_SUBMITTED',entity:'shop_registration_applications',recordId:applicationId,registrationLinkId:link.id,createdAt:now};
 try{
  const out=await db.transact([
   db.tx.add('shop_registration_applications',[application]),
   db.tx.add('shop_compliance_profiles',[compliance]),
   db.tx.add('shop_payout_profiles',[payout]),
   db.tx.update('shop_registration_links',[{id:link.id,record:{...link,tokenHash:null,linkRevision:token(12),usedAt:now,applicationId},if:{linkRevision:link.linkRevision}}]),
   db.tx.add('audit_logs',[audit])
  ]);
  if(out.some((x:any)=>!x?.[0]))throw new Error('transaction_incomplete');
 }catch{await storage.delete(paths);return bad('The registration application could not be committed. No account or workspace was created.',409)}
 await publishPlatformRegistrationAlert(application);
 return res(201,{application:{reference,status:'submitted',track},message:'Your application has been submitted for Super Admin review. No Managing Director account or active shop workspace has been created yet.'});
}],
'POST /api/onboarding/claim':[async ctx=>{
 if(!unsafe(ctx))return bad('Cross-site request rejected.',403);
 const b=obj<any>(ctx.body),claimToken=String(b.claimToken||''),password=String(b.password||''),confirm=String(b.confirmPassword||'');
 if(!/^[a-f0-9]{64}$/i.test(claimToken)||!validPassword(password)||password!==confirm)return bad('Use your approved claim link and enter matching password details that meet the password policy.');
 const tokenHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(claimToken))),x=>x.toString(16).padStart(2,'0')).join('');
 const claims=await find<any>('shop_md_claims','tokenHash',tokenHash),claim=claims[0];
 if(!claim||claim.usedAt||new Date(claim.expiresAt).getTime()<Date.now())return bad('This Managing Director claim link is invalid, expired or already used. Contact the platform administrator.',403);
 const[application]=await db.get<any>('shop_registration_applications',[claim.applicationId],{consistent:true});
 const[user]=await db.get<User>('users',[claim.userId],{consistent:true});
 if(!application||application.status!=='approved'||!user||user.active!==false)return bad('The approved account is unavailable. Contact the platform administrator.',409);
 const now=new Date().toISOString();
 try{
  const out=await db.transact([
   db.tx.update('users',[{id:user.id,record:{...user,passwordHash:await hash(password),active:true,claimedAt:now},if:{active:false}}]),
   db.tx.update('shop_md_claims',[{id:claim.id,record:{...claim,usedAt:now},if:{usedAt:null}}]),
   db.tx.update('shop_registration_applications',[{id:application.id,record:{...application,status:'account_claimed',claimedAt:now},if:{status:'approved'}}]),
   db.tx.add('audit_logs',[{id:'claim_'+claim.id,ownerId:'shopflow_platform',actorId:user.id,actorName:user.name,action:'MANAGING_DIRECTOR_ACCOUNT_CLAIMED',entity:'users',recordId:user.id,createdAt:now}])
  ]);
  if(out.some((x:any)=>!x?.[0]))return bad('Account claiming could not be committed. The link remains subject to verification.',409);
 }catch{return bad('Account claiming could not be committed. No successful activation was confirmed.',409)}
 return res(200,{ok:true,message:'Your Managing Director account is active. You can now sign in using your email and new password.'});
}],
'GET /api/super-admin/dashboard':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const settings=await all<any>('marketplace_settings'),registries=settings.filter(x=>x.recordType==='workspace_registry');
 const applications=(await all<any>('shop_registration_applications')).sort((a,b)=>String(b.submittedAt||'').localeCompare(String(a.submittedAt||'')));
 const users=await all<User>('users'),products=await all<any>('products'),sales=await all<any>('sales'),orders=await all<any>('web_orders');
 const links=await all<any>('shop_registration_links');
 const workspaces=registries.filter(x=>x.workspaceId!=='shopflow_platform').map(w=>{
  const ownerId=String(w.workspaceId||w.ownerId||'');
  const md=users.find(u=>u.ownerId===ownerId&&u.role==='Managing Director');
  const shopProducts=products.filter(x=>x.ownerId===ownerId),shopSales=sales.filter(x=>x.ownerId===ownerId),shopOrders=orders.filter(x=>x.ownerId===ownerId);
  return{id:ownerId,registryId:w.id,name:w.displayName||'Unnamed shop',status:w.status||'active',createdAt:w.createdAt||'',managingDirector:md?{id:md.id,name:md.name,email:md.email,active:md.active!==false}:null,staffCount:users.filter(u=>u.ownerId===ownerId).length,productCount:shopProducts.length,salesCount:shopSales.length,revenue:shopSales.reduce((n,x)=>n+Number(x.total||0),0),openOrders:shopOrders.filter(x=>x.status!=='Paid').length};
 }).sort((a,b)=>a.name.localeCompare(b.name));
 const safeApplications=applications.map(({documents,...a})=>({...a,documents:(documents||[]).map((d:any)=>({kind:d.kind,name:d.name,contentType:d.contentType,uploadedAt:d.uploadedAt}))}));
 const registrationLinks:any[]=links.map((link:any)=>{const{tokenHash,...rest}=link;return{...rest,status:registrationLinkStatus(link)};}).sort((left:any,right:any)=>String(right.createdAt||'').localeCompare(String(left.createdAt||'')));
 const adminIds=new Set(users.filter(user=>user.role==='Super Admin'&&user.active!==false).map(user=>user.id));
 const platformNotifications=(await db.list<any>('notifications',{limit:500})).items.filter(item=>item.ownerId==='shopflow_platform'&&adminIds.has(item.userId)).sort((a,b)=>String(b.createdAt||'').localeCompare(String(a.createdAt||''))).slice(0,50);
 return res(200,{stats:{shops:workspaces.length,activeShops:workspaces.filter(w=>w.status!=='suspended').length,suspendedShops:workspaces.filter(w=>w.status==='suspended').length,applications:applications.length,pendingApplications:applications.filter(a=>['submitted','under_review'].includes(a.status)).length,managingDirectors:users.filter(u=>u.role==='Managing Director').length,platformRevenue:workspaces.reduce((n,w)=>n+w.revenue,0),unreadNotifications:platformNotifications.filter(item=>!item.readAt).length},workspaces,applications:safeApplications,registrationLinks,notifications:platformNotifications});
}],
'POST /api/super-admin/notifications/read':[async ctx=>{
 const s=await session(ctx);const denied=guard(ctx,s,'platform');if(denied)return denied;if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const id=String(obj<any>(ctx.body).id||''),[notification]=await db.get<any>('notifications',[id],{consistent:true});
 if(!notification||notification.ownerId!=='shopflow_platform'||notification.userId!==s.userId)return bad('Platform notification not found.',404);
 if(!notification.readAt&&!await setRecord('notifications',id,{...notification,readAt:new Date().toISOString()}))return bad('Notification could not be marked as read.',409);
 return res(200,{ok:true});
}],
'POST /api/super-admin/registration-links':[async ctx=>{
 const s=await session(ctx);const denied=guard(ctx,s,'platform');if(denied)return denied;if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const b=obj<any>(ctx.body),days=Number(b.expiresInDays||7);
 if(!Number.isInteger(days)||days<1||days>30)return bad('Registration link expiry must be between 1 and 30 days.',400);
 const raw=token(32),tokenHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(raw))),x=>x.toString(16).padStart(2,'0')).join(''),now=new Date(),id='srl_'+token(12),expiresAt=new Date(now.getTime()+days*86400000).toISOString();
 const link={id,tokenHash,linkRevision:token(12),createdBy:s.userId,createdByName:s.user.name,createdAt:now.toISOString(),expiresAt,usedAt:null,revokedAt:null,applicationId:null};
 if(!(await create('shop_registration_links',link)))return bad('Registration link could not be created.',500);
 await create('audit_logs',{id:'link_'+id,ownerId:'shopflow_platform',actorId:s.userId,actorName:s.user.name,action:'SHOP_REGISTRATION_LINK_CREATED',entity:'shop_registration_links',recordId:id,expiresAt,createdAt:now.toISOString()});
 return res(201,{link:{id,expiresAt,url:SHOPFLOW_PUBLIC_ORIGIN+'/?shopRegistration='+raw},message:'One-time registration link created. Share it only with the intended business owner.'});
}],
'POST /api/super-admin/registration-links/refresh':[async ctx=>{
 const s=await session(ctx);const denied=guard(ctx,s,'platform');if(denied)return denied;if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const id=String(obj<any>(ctx.body).id||'');
 if(!id)return bad('Select a registration link to continue.',400);
 const link=await getRegistrationLink(id);
 if(!link)return bad('Registration link not found. Refresh the issued-links list and try again.',404);
 const currentStatus=registrationLinkStatus(link);
 if(currentStatus!=='available')return bad('This registration link is '+currentStatus+' and cannot be renewed. The list has been refreshed with its current status.',409);
 const raw=token(32),tokenHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(raw))),x=>x.toString(16).padStart(2,'0')).join(''),now=new Date().toISOString();
 const updated={...link,tokenHash,linkRevision:token(12),tokenRotatedAt:now,tokenRotatedBy:s.userId};
 let out:any;
 try{
  out=await db.transact([db.tx.update('shop_registration_links',[{id,record:updated,if:{linkRevision:link.linkRevision}}])]);
 }catch(error){
  if(isAppDatabaseError(error)&&(error.code==='AppDatabaseConditionFailed'||error.code==='AppDatabaseConflict'))return bad('The registration link changed while it was being renewed. Refresh the list and try again.',409);
  throw error;
 }
 if(!out?.[0]?.[0])return bad('The registration link changed or was used. Refresh the list and try again.',409);
 await create('audit_logs',{id:'renew_'+id+'_'+token(4),ownerId:'shopflow_platform',actorId:s.userId,actorName:s.user.name,action:'SHOP_REGISTRATION_LINK_RENEWED',entity:'shop_registration_links',recordId:id,createdAt:now});
 return res(200,{link:{id,expiresAt:link.expiresAt,url:SHOPFLOW_PUBLIC_ORIGIN+'/?shopRegistration='+raw},message:'The unused registration link token was renewed. The previous URL is no longer valid.'});
}],
'POST /api/super-admin/registration-links/revoke':[async ctx=>{
 const s=await session(ctx);const denied=guard(ctx,s,'platform');if(denied)return denied;if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const id=String(obj<any>(ctx.body).id||'');
 if(!id)return bad('Select a registration link to continue.',400);
 const link=await getRegistrationLink(id);
 if(!link)return bad('Registration link not found. Refresh the issued-links list and try again.',404);
 const currentStatus=registrationLinkStatus(link);
 if(currentStatus!=='available')return bad('This registration link is '+currentStatus+' and cannot be revoked. The list has been refreshed with its current status.',409);
 const now=new Date().toISOString();
 let out:any;
 try{
  out=await db.transact([db.tx.update('shop_registration_links',[{id,record:{...link,tokenHash:null,linkRevision:token(12),revokedAt:now},if:{linkRevision:link.linkRevision}}])]);
 }catch(error){
  if(isAppDatabaseError(error)&&(error.code==='AppDatabaseConditionFailed'||error.code==='AppDatabaseConflict'))return bad('The registration link changed while you were revoking it. Refresh the list and check its current status.',409);
  throw error;
 }
 if(!out?.[0]?.[0])return bad('The registration link changed while you were revoking it. Refresh the list and check its current status.',409);
 await create('audit_logs',{id:'revoke_'+id+'_'+token(4),ownerId:'shopflow_platform',actorId:s.userId,actorName:s.user.name,action:'SHOP_REGISTRATION_LINK_REVOKED',entity:'shop_registration_links',recordId:id,createdAt:now});
 return res(200,{ok:true});
}],
'POST /api/super-admin/applications/decision':[async ctx=>{
 const s=await session(ctx);const denied=guard(ctx,s,'platform');if(denied)return denied;if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const b=obj<any>(ctx.body),id=String(b.applicationId||''),decision=String(b.decision||''),reason=String(b.reason||'').trim();
 if(!['approve','reject'].includes(decision))return bad('Choose approve or reject.',400);
 const[application]=await db.get<any>('shop_registration_applications',[id],{consistent:true});
 if(!application||!['submitted','under_review'].includes(application.status))return bad('A pending registration application was not found.',404);
 const now=new Date().toISOString();
 if(decision==='reject'){
  if(reason.length<5)return bad('Provide a reason for rejecting this application.',400);
  if(!(await setRecord('shop_registration_applications',id,{...application,status:'rejected',reviewedBy:s.userId,reviewedAt:now,rejectionReason:reason})))return bad('Application rejection could not be saved.',409);
  await create('audit_logs',{id:'application_reject_'+id,ownerId:'shopflow_platform',actorId:s.userId,actorName:s.user.name,action:'SHOP_REGISTRATION_REJECTED',entity:'shop_registration_applications',recordId:id,reason,createdAt:now});
  return res(200,{ok:true,status:'rejected'});
 }
 if((await find<User>('users','email',String(application.email||''))).length)return bad('An account already exists for this email. Resolve the duplicate before approval.',409);
 const userId='md_'+token(18),claimId='mdclaim_'+token(14),raw=token(32),tokenHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(raw))),x=>x.toString(16).padStart(2,'0')).join(''),expiresAt=new Date(Date.now()+7*86400000).toISOString();
 const account:User={id:userId,name:application.ownerName,email:application.email,passwordHash:await hash(token(40)),role:'Managing Director',active:false,ownerId:application.workspaceId,createdAt:now};
 const registry={id:'workspace_'+application.workspaceId,recordType:'workspace_registry',workspaceId:application.workspaceId,ownerId:application.workspaceId,displayName:application.shopName,status:'active',ownerUserId:userId,createdAt:now,approvedAt:now,approvedBy:s.userId};
 const shopSettings={id:application.workspaceId,ownerId:application.workspaceId,storeName:application.shopName,city:application.town||'',marketplaceEnabled:false,onboardingStatus:'approved_pending_owner_claim',createdAt:now};
 const claim={id:claimId,tokenHash,applicationId:id,workspaceId:application.workspaceId,userId,createdAt:now,expiresAt,usedAt:null};
 const audit={id:'application_approve_'+id,ownerId:'shopflow_platform',actorId:s.userId,actorName:s.user.name,action:'SHOP_REGISTRATION_APPROVED_AND_MD_ACCOUNT_CREATED',entity:'shop_registration_applications',recordId:id,createdAt:now};
 try{
  const out=await db.transact([
   db.tx.add('users',[account]),
   db.tx.add('marketplace_settings',[registry,shopSettings]),
   db.tx.add('shop_md_claims',[claim]),
   db.tx.update('shop_registration_applications',[{id,record:{...application,status:'approved',reviewedBy:s.userId,reviewedAt:now,managingDirectorUserId:userId},if:{status:application.status}}]),
   db.tx.add('audit_logs',[audit])
  ]);
  if(out.some((x:any)=>!x?.[0]))return bad('Approval and account provisioning did not commit completely.',409);
 }catch{return bad('Approval and account provisioning could not be committed. No Managing Director account activation was confirmed.',409)}
 return res(200,{ok:true,status:'approved',managingDirector:{id:userId,name:account.name,email:account.email,active:false},claimUrl:SHOPFLOW_PUBLIC_ORIGIN+'/?claim='+raw,claimExpiresAt:expiresAt,message:'Registration approved. A disabled Managing Director account was created and is awaiting its one-time owner claim.'});
}],
'POST /api/super-admin/workspaces/status':[async ctx=>{
 const s=await session(ctx);const denied=guard(ctx,s,'platform');if(denied)return denied;if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const b=obj<any>(ctx.body),workspaceId=String(b.workspaceId||''),status=String(b.status||'');
 if(!/^[A-Za-z0-9_-]{3,120}$/.test(workspaceId)||!['active','suspended'].includes(status))return bad('Workspace and status are invalid.',400);
 const registryId='workspace_'+workspaceId,[registry]=await db.get<any>('marketplace_settings',[registryId],{consistent:true});
 if(!registry||registry.recordType!=='workspace_registry')return bad('Shop workspace was not found.',404);
 if(!(await setRecord('marketplace_settings',registryId,{...registry,status,updatedAt:new Date().toISOString(),updatedBy:s.userId})))return bad('Workspace status could not be saved.',409);
 await create('audit_logs',{id:'workspace_status_'+workspaceId+'_'+token(4),ownerId:'shopflow_platform',actorId:s.userId,actorName:s.user.name,action:status==='suspended'?'WORKSPACE_SUSPENDED':'WORKSPACE_REACTIVATED',entity:'workspaces',recordId:workspaceId,createdAt:new Date().toISOString()});
 return res(200,{ok:true,status});
}],
'GET /api/super-admin/applications/document':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const query=ctx.event?.queryStringParameters||{},applicationId=String(query.applicationId||''),kind=String(query.kind||'');
 const[application]=await db.get<any>('shop_registration_applications',[applicationId],{consistent:true});
 if(!application)return bad('Registration application not found.',404);
 const document=(application.documents||[]).find((item:any)=>item.kind===kind);
 if(!document||!String(document.storagePath||'').startsWith('storage://onboarding/'+applicationId+'/'))return bad('Private application evidence was not found.',404);
 const[entry]=await storage.url([document.storagePath.slice('storage://'.length)]);
 if(!entry?.url)return bad('A secure document viewing URL could not be created.',503);
 return res(200,{url:entry.url,expiresInSeconds:300});
}],
'GET /api/super-admin/workspaces/detail':[async ctx=>{
 const s=await session(ctx,false);if(!s)return bad('Sign in to continue.',401);if(s.user.role!=='Super Admin')return bad('Platform Super Admin access is required.',403);
 const workspaceId=String(ctx.event?.queryStringParameters?.workspaceId||'');if(!workspaceId)return bad('Workspace ID is required.',400);
 const[registry]=await db.get<any>('marketplace_settings',['workspace_'+workspaceId],{consistent:true});if(!registry||registry.recordType!=='workspace_registry')return bad('Workspace not found.',404);
 const [users,products,sales,orders,settings,payouts]=await Promise.all([owned<User>('users',workspaceId),owned<any>('products',workspaceId),owned<any>('sales',workspaceId),owned<any>('web_orders',workspaceId),db.get<any>('marketplace_settings',[workspaceId],{consistent:true}),owned<any>('shop_payout_profiles',workspaceId)]);
 const [configuration]=settings;
 return res(200,{workspace:{id:workspaceId,name:registry.displayName,status:registry.status,createdAt:registry.createdAt,marketplaceEnabled:configuration?.marketplaceEnabled===true,location:configuration?.city||''},managingDirector:users.find(u=>u.role==='Managing Director')?clean([users.find(u=>u.role==='Managing Director')])[0]:null,staff:clean(users),metrics:{products:products.length,sales:sales.length,revenue:sales.reduce((n,x)=>n+Number(x.total||0),0),onlineOrders:orders.length,pendingOrders:orders.filter(x=>x.status!=='Paid').length},payoutProfiles:payouts.map(p=>({id:p.id,payoutType:p.payoutType,provider:p.provider,accountName:p.accountName,accountNumberLast4:p.accountNumberLast4,verificationStatus:p.verificationStatus}))});
}],

'GET /api/auth/session':[async ctx=>{
 const s=await session(ctx,false);if(!s)return res(200,{authenticated:false});
 let user=s.user;
 if(user.id==='initial_managing_director'&&user.role==='Managing Director'){
  const migrated={...user,role:'Super Admin'};
  if(!(await setRecord('users',s.userId,migrated)))return bad('The legacy platform administrator account could not be migrated. Sign in again or contact platform support.',503);
  user=migrated;
  await create('audit_logs',{id:'legacy_super_admin_migration',ownerId:'shopflow_platform',actorId:s.userId,actorName:user.name,action:'LEGACY_INITIAL_MANAGING_DIRECTOR_PROMOTED_TO_SUPER_ADMIN',entity:'platform_accounts',recordId:s.userId,legacyWorkspaceOwnerId:user.ownerId,createdAt:new Date().toISOString()});
 }
 return res(200,{authenticated:true,csrfToken:s.csrfToken,user:{id:user.id,name:user.name,email:user.email,role:user.role,avatarUrl:user.avatarUrl||''}});
}],
});


async function authRateLimitKey(kind:string,value:string){
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));
 const hex=Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,'0')).join('');
 return 'login_'+kind+'_'+hex.slice(0,40);
}
async function loginRateLimit(email:string,ip:string,recordFailure=false){
 const now=Date.now(),windowMs=15*60*1000,buckets=[{id:await authRateLimitKey('email',email),limit:6},{id:ip?await authRateLimitKey('ip',ip):'',limit:20}].filter(x=>x.id);
 let retryAfterSeconds=0;
 for(const bucket of buckets){
  const [current]=await db.get<any>('auth_rate_limits',[bucket.id],{consistent:true});
  if(!recordFailure){if(Number(current?.lockUntil||0)>now)retryAfterSeconds=Math.max(retryAfterSeconds,Math.ceil((Number(current.lockUntil)-now)/1000));continue;}
  const active=current&&now-Number(current.windowStart||0)<windowMs,attempts=(active?Number(current.attempts||0):0)+1;
  const lockMs=attempts>=bucket.limit*3?60*60*1000:attempts>=bucket.limit*2?15*60*1000:attempts>=bucket.limit?5*60*1000:0;
  const record={id:bucket.id,kind:bucket.id.includes('_email_')?'email':'ip',attempts,windowStart:active?Number(current.windowStart):now,lockUntil:lockMs?now+lockMs:0,updatedAt:new Date(now).toISOString()};
  if(!await setRecord('auth_rate_limits',bucket.id,record))throw new Error('AUTH_RATE_LIMIT_STORE_UNAVAILABLE');
  if(lockMs)retryAfterSeconds=Math.max(retryAfterSeconds,Math.ceil(lockMs/1000));
 }
 return{blocked:retryAfterSeconds>0,retryAfterSeconds};
}
async function clearLoginRateLimit(email:string){
 const id=await authRateLimitKey('email',email);
 await db.delete('auth_rate_limits',[id]);
}

function allowedBrowserOrigin(event:any){const h=headers(event),requestOrigin=h.origin;return requestOrigin&&origin(h,event)===requestOrigin?requestOrigin:null;}
const CORS_HEADERS = {
  'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'access-control-allow-headers': 'Content-Type, X-CSRF-Token',
  'access-control-allow-credentials': 'true',
  'access-control-max-age': '600',
  'vary': 'Origin',
};

const handleRequest = async (event: any) => {
  const h = headers(event);
  const requestOrigin = h.origin;
  const allowedOrigin = allowedBrowserOrigin(event);
  const method = String(event?.httpMethod || event?.requestContext?.http?.method || '').toUpperCase();
  const corsHeaders = allowedOrigin
    ? { ...CORS_HEADERS, 'access-control-allow-origin': allowedOrigin }
    : { vary: 'Origin' };

  if (method === 'OPTIONS') {
    if (!allowedOrigin) return res(403, { error: 'Origin not allowed.' }, { vary: 'Origin' });
    return { statusCode: 204, headers: { ...corsHeaders }, body: '' };
  }

  const requestPath = String(event?.path || event?.rawPath || event?.requestContext?.http?.path || '').split('?')[0];

  if (method === 'POST' && requestPath === '/api/integrations/paystack/webhook') {
    let rawBody = typeof event?.body === 'string' ? event.body : '';
    try {
      if (event?.isBase64Encoded && rawBody) rawBody = new TextDecoder().decode(Uint8Array.from(atob(rawBody), character => character.charCodeAt(0)));
      if (!rawBody || rawBody.length > 65536) return res(400, { error: 'Invalid Paystack webhook payload.' });
      const payload = obj<any>(JSON.parse(rawBody)),data = obj<any>(payload.data);
      const metadata = typeof data.metadata === 'string' ? JSON.parse(data.metadata || '{}') : obj<any>(data.metadata);
      const reference=String(data.reference||''),workspaceId=String(metadata.shopflowWorkspaceId||'');
      if(!/^[A-Za-z0-9.=-]{8,100}$/.test(reference)||!workspaceId)return res(400,{error:'Paystack webhook reference or workspace metadata is invalid.'});
      const [referenceIndex]=await db.get<any>('integration_secrets',['paystack_ref_'+reference],{consistent:true});
      if(!referenceIndex||referenceIndex.provider!=='PAYSTACK'||referenceIndex.workspaceId!==workspaceId||referenceIndex.reference!==reference)return res(404,{error:'Paystack reference is not registered to this workspace.'});
      const isPos=referenceIndex.channel==='POS'||!!referenceIndex.paymentAttemptId;
      let record:any=null;
      if(isPos){
        const attemptId=String(referenceIndex.paymentAttemptId||metadata.shopflowPaymentAttemptId||'');
        if(!/^pospay_[A-Za-z0-9_-]{16,80}$/.test(attemptId)||metadata.shopflowChannel!=='POS'||metadata.shopflowPaymentAttemptId!==attemptId)return res(400,{error:'Paystack POS webhook metadata is invalid.'});
        const [attempt]=await db.get<any>('payment_records',[attemptId],{consistent:true});record=attempt;
        if(!record||record.ownerId!==workspaceId||record.paymentProvider!=='PAYSTACK'||record.paystackReference!==reference||record.paystackCredentialId!==referenceIndex.credentialId)return res(404,{error:'Paystack POS payment attempt was not found.'});
      }else{
        const orderId=String(referenceIndex.orderId||metadata.shopflowOrderId||'');
        if(!/^weborder_[A-Za-z0-9_-]{16,80}$/.test(orderId)||metadata.shopflowOrderId!==orderId||(metadata.shopflowChannel&&metadata.shopflowChannel!=='ONLINE_ORDER'))return res(400,{error:'Paystack online-order webhook metadata is invalid.'});
        const [order]=await db.get<any>('web_orders',[orderId],{consistent:true});record=order;
        if(!record||record.ownerId!==workspaceId||record.paymentProvider!=='PAYSTACK'||record.paystackReference!==reference||record.paystackCredentialId!==referenceIndex.credentialId)return res(404,{error:'Paystack online order was not found.'});
      }
      const merchant=await loadWorkspacePaystackCredentials(workspaceId,String(referenceIndex.credentialId||''));
      if(!merchant||merchant.merchantAccountId!==record.paystackMerchantAccountId)return res(503,{error:'Original workspace Paystack credentials are unavailable.'});
      const signature=headers(event)['x-paystack-signature']||'';
      if(!await verifyPaystackSignature(rawBody,signature,merchant.credentials.secretKey))return res(401,{error:'Paystack webhook signature is invalid.'});
      if(String(payload.event||'')!=='charge.success')return res(200,{received:true,ignored:true});
      if(isPos){
        const verification=await reconcilePaystackPosAttempt(record);
        let result:any={};try{result=obj<any>(JSON.parse(verification.body||'{}'))}catch{}
        if(verification.statusCode>=500)return res(503,{received:true,verified:false,retry:true});
        return res(200,{received:true,verified:result.status==='Paid',status:result.status||'Pending',channel:'POS'});
      }
      const verification=await routeHandler({httpMethod:'POST',path:'/api/storefront/order-status/reconcile',headers:{'content-type':'application/json'},queryStringParameters:{store:workspaceId,order:String(record.id)}});
      if(!verification||verification.statusCode>=500)return res(503,{received:true,verified:false,retry:true});
      let result:any={};try{result=obj<any>(JSON.parse(verification.body||'{}'))}catch{}
      return res(200,{received:true,verified:result.status==='Paid',status:result.status||'Pending',channel:'ONLINE_ORDER'});
    }catch(error){
      console.error('PAYSTACK_WEBHOOK_FAILURE '+JSON.stringify({code:String((error as any)?.code||'').slice(0,40)}));
      return res(400,{error:'Paystack webhook could not be processed.'});
    }
  }

  if (method === 'GET' && requestPath === '/api/integrations/paystack/callback') {
    const query=event?.queryStringParameters||{},reference=String(query.reference||query.trxref||'');
    if (!/^[A-Za-z0-9.=-]{8,100}$/.test(reference)) return res(400,{error:'Paystack callback reference is invalid.'});
    const [referenceIndex]=await db.get<any>('integration_secrets',['paystack_ref_'+reference],{consistent:true});
    if(!referenceIndex||referenceIndex.provider!=='PAYSTACK'||!referenceIndex.orderId||!referenceIndex.workspaceId)return res(404,{error:'Paystack order reference was not found.'});
    const [order]=await db.get<any>('web_orders',[referenceIndex.orderId],{consistent:true});
    if(!order||order.ownerId!==referenceIndex.workspaceId||order.paymentProvider!=='PAYSTACK'||order.paystackReference!==reference||referenceIndex.credentialId!==order.paystackCredentialId)return res(404,{error:'Paystack order reference was not found.'});
    const verification=await routeHandler({httpMethod:'POST',path:'/api/storefront/order-status/reconcile',headers:{'content-type':'application/json'},queryStringParameters:{store:String(order.ownerId),order:String(order.id)}});
    let result:any={};try{result=obj<any>(JSON.parse(verification?.body||'{}'))}catch{}
    const host=normalizeMtnCallbackHost(order.paystackCallbackHost);if(!host)return res(503,{error:'The original Paystack callback host is unavailable. Track this order using its reference.'});
    const location='https://'+host+'/?paystack=returned&order='+encodeURIComponent(order.id)+'&store='+encodeURIComponent(order.ownerId)+'&status='+encodeURIComponent(String(result.status||'Pending'));
    return{statusCode:302,headers:{Location:location,'Cache-Control':'no-store'},body:''};
  }

  if (['POST', 'PUT'].includes(method) && requestPath === '/api/integrations/mtn/callback') {
    let callback: any;
    try {
      let rawBody = typeof event?.body === 'string' ? event.body : '';
      if (event?.isBase64Encoded && rawBody) {
        rawBody = new TextDecoder().decode(Uint8Array.from(atob(rawBody), (character) => character.charCodeAt(0)));
      }
      if (!rawBody || rawBody.length > 16384) return res(400, { error: 'Invalid MTN callback payload.' });
      callback = obj<any>(JSON.parse(rawBody));
    } catch {
      return res(400, { error: 'Invalid MTN callback payload.' });
    }

    const query = event?.queryStringParameters || {};
    const orderId = String(query.order || '');
    const callbackReference = String(query.reference || '');
    if (!/^weborder_[A-Za-z0-9_-]{16,80}$/.test(orderId) || !/^[0-9a-f-]{36}$/i.test(callbackReference)) {
      return res(400, { error: 'MTN callback correlation is invalid.' });
    }

    const [order] = await db.get<any>('web_orders', [orderId], { consistent: true });
    if (!order || order.mtnReference !== callbackReference) {
      return res(404, { error: 'MTN callback transaction was not found.' });
    }
    if (callback.externalId !== undefined && String(callback.externalId) !== orderId) {
      return res(400, { error: 'MTN callback order reference does not match.' });
    }
    const payloadReference = callback.referenceId || callback.reference;
    if (payloadReference !== undefined && String(payloadReference) !== order.mtnReference) {
      return res(400, { error: 'MTN callback payment reference does not match.' });
    }
    if (callback.amount !== undefined && Math.round(Number(callback.amount) * 100) !== Math.round(Number(order.providerAmount) * 100)) {
      return res(400, { error: 'MTN callback amount does not match the order.' });
    }
    if (callback.currency !== undefined && String(callback.currency).toUpperCase() !== String(order.providerCurrency || 'EUR').toUpperCase()) {
      return res(400, { error: 'MTN callback currency does not match the order.' });
    }
    const callbackPayer = callback.payer?.partyId;
    if (callbackPayer !== undefined && normalizeGhanaPhone(callbackPayer) !== normalizeGhanaPhone(order.phone)) {
      return res(400, { error: 'MTN callback payer does not match the order.' });
    }

    const receivedAt = new Date().toISOString();
    const [stored] = await db.tx.update('web_orders', [{
      id: orderId,
      record: {
        mtnCallbackReceivedAt: receivedAt,
        mtnCallbackStatus: String(callback.status || '').toUpperCase().slice(0, 24),
        mtnCallbackVerification: 'pending',
      },
      if: { mtnReference: order.mtnReference },
    }], { patch: true });
    if (!stored) return res(409, { error: 'MTN callback could not be durably recorded.' });

    let verification: any;
    try {
      verification = await routeHandler({
        httpMethod: 'POST',
        path: '/api/storefront/order-status/reconcile',
        headers: { 'content-type': 'application/json' },
        queryStringParameters: { store: String(order.ownerId), order: orderId },
      });
    } catch {
      verification = null;
    }

    if (!verification || verification.statusCode >= 400) {
      await db.tx.update('web_orders', [{
        id: orderId,
        record: {
          mtnCallbackVerification: 'pending_manual_recovery',
          mtnCallbackLastAttemptAt: new Date().toISOString(),
        },
        if: { mtnReference: order.mtnReference },
      }], { patch: true });
      return res(202, { accepted: true, verified: false, recoveryRequired: true });
    }

    let verifiedResult: any = {};
    try {
      verifiedResult = obj<any>(JSON.parse(verification.body || '{}'));
    } catch {}
    const terminal = ['Paid', 'Failed'].includes(String(verifiedResult.status || ''));
    await db.tx.update('web_orders', [{
      id: orderId,
      record: {
        mtnCallbackVerification: terminal ? 'verified' : 'provider_status_pending',
        mtnCallbackVerifiedStatus: String(verifiedResult.status || '').slice(0, 24),
        mtnCallbackVerifiedAt: new Date().toISOString(),
      },
      if: { mtnReference: order.mtnReference },
    }], { patch: true });

    return res(200, { accepted: true, verified: terminal, recoveryRequired: !terminal, status: verifiedResult.status || 'Pending' });
  }

  try {
    const response = await routeHandler(event);
    return {
      ...response,
      headers: { ...(response?.headers || {}), ...corsHeaders },
    };
  } catch (cause: any) {
    const requestId = String(event?.requestContext?.requestId || event?.requestContext?.requestId || token(8)).slice(0, 100);
    const code = String(cause?.code || '');
    const unavailable = ['AppDatabaseGatewayUnavailable', 'AppDatabaseQuotaExceeded', 'ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND'].includes(code);
    console.error('UNHANDLED_API_FAILURE ' + JSON.stringify({ requestId, method, path: String(event?.path || event?.rawPath || '').slice(0, 180), code: code.slice(0, 40) }));
    return res(unavailable ? 503 : 500, {
      error: unavailable ? 'A required service is temporarily unavailable. No successful change was confirmed; retry shortly.' : 'An unexpected server error occurred. No successful change was confirmed.',
      code: unavailable ? 'SERVICE_UNAVAILABLE' : 'INTERNAL_ERROR',
      requestId,
      retrySafe: false
    }, corsHeaders);
  }
};

export const handler = async (event: any) => {
  { const o = origin(headers(event), event); if (o) SHOPFLOW_PUBLIC_ORIGIN = o; }
  try {
    return await handleRequest(event);
  } catch (cause: any) {
    const requestId = String(event?.requestContext?.requestId || token(8)).slice(0, 100);
    const code = String(cause?.code || '');
    const unavailable = ['AppDatabaseGatewayUnavailable', 'AppDatabaseQuotaExceeded', 'ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND'].includes(code);
    const requestOrigin = headers(event).origin;
    const allowedOrigin = allowedBrowserOrigin(event);
    const cors = allowedOrigin ? { ...CORS_HEADERS, 'access-control-allow-origin': allowedOrigin } : { vary: 'Origin' };
    console.error('UNHANDLED_REQUEST_FAILURE ' + JSON.stringify({ requestId, method: String(event?.httpMethod || '').slice(0, 12), path: String(event?.path || event?.rawPath || '').slice(0, 180), code: code.slice(0, 40) }));
    return res(unavailable ? 503 : 500, {
      error: unavailable ? 'A required service is temporarily unavailable. No successful change was confirmed; retry shortly.' : 'An unexpected server error occurred. No successful change was confirmed.',
      code: unavailable ? 'SERVICE_UNAVAILABLE' : 'INTERNAL_ERROR',
      requestId,
      retrySafe: false
    }, cors);
  }
};


