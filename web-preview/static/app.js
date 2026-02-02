// Helper: parse utm_* and source from URL
function parseUrlParams(){
  const params = new URLSearchParams(window.location.search);
  const out = {};
  for(const [k,v] of params.entries()){
    if(k.startsWith('utm_')) out.utm = out.utm ? out.utm + '&' + k + '=' + v : `${k}=${v}`;
    if(k==='source') out.source = v;
  }
  return out;
}

// Signup form handling
const signupForm = document.querySelector('form[action="#signup"]');
const signupMsgElem = document.getElementById('signup-msg');
if(signupForm){
  signupForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const emailInput = signupForm.querySelector('input[type="email"]');
    const btn = signupForm.querySelector('button');
    const msgAreaId = 'signup-msg';
    // ensure visible
    let msg = document.getElementById(msgAreaId);
    if(!msg){ msg = document.createElement('div'); msg.id = msgAreaId; msg.className='small muted'; signupForm.parentNode.appendChild(msg); }

    const email = emailInput.value.trim();
    if(!email){ msg.textContent='Please enter a valid email.'; msg.style.display='block'; console.log('[SIGNUP] validation failed'); return; }
    const params = parseUrlParams();
    btn.disabled = true; btn.textContent='Joining...';
    try{
      const res = await fetch('/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,source:params.source||'',utm:params.utm||''})});
      const data = await res.json().catch(()=>null);
      console.log('[SIGNUP] response', res.status, data);
      if(res.ok && data && data.ok){
        msg.textContent = 'Thanks — check your inbox for confirmation (or keep an eye on our weekly digests).';
        emailInput.value='';
        console.log('[SIGNUP] success', data);
        // mark session so refresh shows welcome
        sessionStorage.setItem('trendcurator_just_signed_up', '1');
        // refresh latest issue, reveal and scroll to it
        await refreshLatestPick();
        revealAndScrollHero();
      } else if(data && data.error && data.error.toLowerCase().includes('exists')){
        msg.textContent = 'You are already subscribed — thanks!';
      } else {
        msg.textContent = (data && data.error) ? data.error : 'Signup failed — try again later.';
      }
    }catch(err){
      console.error('[SIGNUP] network error', err);
      msg.textContent = 'Network error — try again.';
    } finally {
      msg.style.display='block';
      btn.disabled = false; btn.textContent='Join — it\'s free';
    }
  });
}

// Admin panel: prompt for token, store in sessionStorage, attach to publish calls
function ensureAdminToken(){
  let token = sessionStorage.getItem('tc_admin_token');
  if(!token){
    token = prompt('Enter ADMIN_TOKEN (session only)');
    if(token) sessionStorage.setItem('tc_admin_token', token);
  }
  return token;
}

async function savePick(e){
  e.preventDefault();
  const title=document.getElementById('pick-title').value.trim();
  const reason=document.getElementById('pick-reason').value.trim();
  if(!title||!reason){document.getElementById('editor-msg').textContent='Please provide title and reason.';return false}

  const adminToken = ensureAdminToken();
  if(!adminToken){ document.getElementById('editor-msg').textContent='Publish cancelled: admin token required.'; return false }

  const payload = { title, description: title, reason, link: '', score: 80 };
  const btn = e.submitter || document.querySelector('#editor button');
  btn.disabled = true; btn.textContent='Publishing...';
  try{
    const res = await fetch('/publish',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':adminToken},body:JSON.stringify(payload)});
    const data = await res.json();
    if(res.ok && data.ok){
      document.getElementById('editor-msg').textContent = 'Published — issue id: ' + data.id;
      // refresh latest pick display
      await refreshLatestPick();
    } else {
      document.getElementById('editor-msg').textContent = data.error || 'Publish failed';
      if(res.status===401) sessionStorage.removeItem('tc_admin_token');
    }
  }catch(err){
    console.error(err);
    document.getElementById('editor-msg').textContent = 'Network error during publish.';
  } finally{
    btn.disabled = false; btn.textContent='Save (admin)';
  }
  return false;
}

let __latest_issue = null;

// Refresh latest pick display from GET /issues -> first item
async function refreshLatestPick(){
  try{
    const res = await fetch('/issues');
    if(!res.ok) return;
    const issues = await res.json();
    if(issues && issues.length){
      const latest = issues[0];
      __latest_issue = latest;
      // Update hero and meta
      const hero = document.querySelector('.hero');
      if(hero) hero.textContent = latest.title;
      const titleEl = document.querySelector('.meta div div');
      if(titleEl) titleEl.textContent = latest.title;
      const mutedEl = document.querySelector('.meta .muted');
      if(mutedEl) mutedEl.textContent = latest.reason + ((latest.score!==undefined && latest.score!==null) ? (' — Recommender score: ' + latest.score) : '');
      // ensure CTA link present
      let ctaLink = document.querySelector('.meta .product-cta');
      if(!ctaLink){
        ctaLink = document.createElement('a');
        ctaLink.className = 'product-cta small';
        ctaLink.style.marginLeft = '12px';
        ctaLink.style.color = 'var(--accent)';
        ctaLink.style.fontWeight = '700';
        const metaHeader = document.querySelector('.meta > div');
        if(metaHeader) metaHeader.appendChild(ctaLink);
      }
      if(__latest_issue.link){
        ctaLink.href = __latest_issue.link;
        ctaLink.textContent = 'View product';
        ctaLink.target = '_blank';
        ctaLink.rel = 'noopener noreferrer';
      } else {
        ctaLink.href = '#';
        ctaLink.textContent = 'Learn more';
      }
    } else {
      // no issues yet — show friendly placeholder
      __latest_issue = null;
      const hero = document.querySelector('.hero');
      if(hero) hero.textContent = 'No picks yet';
      const titleEl = document.querySelector('.meta div div');
      if(titleEl) titleEl.textContent = 'No picks yet — subscribe to get the first curated pick.';
      const mutedEl = document.querySelector('.meta .muted');
      if(mutedEl) mutedEl.textContent = 'We\'re preparing the first issue. Join the list to be notified.';
      // remove existing CTA if any
      const ctaLink = document.querySelector('.meta .product-cta');
      if(ctaLink) ctaLink.remove();
    }
  }catch(e){ console.error('refresh error',e); }
}

// Helper to reveal hero and scroll (with highlight)
function revealAndScrollHero(isWelcome){
  const hero = document.querySelector('.hero');
  const titleEl = document.querySelector('.meta div div');
  const mutedEl = document.querySelector('.meta .muted');
  if(!__latest_issue) return;
  if(titleEl) titleEl.textContent = __latest_issue.title;
  if(mutedEl) mutedEl.textContent = __latest_issue.reason + ((__latest_issue.score!==undefined && __latest_issue.score!==null) ? (' — Recommender score: ' + __latest_issue.score) : '');
  if(hero) hero.textContent = __latest_issue.title;
  // show welcome if just signed up
  if(isWelcome){
    const msg = document.getElementById('signup-msg');
    if(msg){ msg.textContent = 'Welcome — here\'s your free pick below.'; msg.style.opacity=1; setTimeout(()=>{ msg.style.transition='opacity 1s'; msg.style.opacity=0.9; }, 200); }
    // clear session flag so it only shows once
    sessionStorage.removeItem('trendcurator_just_signed_up');
  }
  // scroll into view
  const el = document.querySelector('.card');
  el && el.scrollIntoView({behavior:'smooth',block:'center'});
  // brief highlight
  const orig = el.style.boxShadow;
  el.style.transition = 'box-shadow 0.25s ease';
  el.style.boxShadow = '0 6px 20px rgba(95,179,200,0.12)';
  setTimeout(()=>{ el.style.boxShadow = orig; }, 1200);
}

// Helper to render admin panel when needed
function renderAdminPanel(){
  const adminHtml = `
  <div class="card" id="admin-card">
    <strong class="muted">Admin: This week's pick (admin only)</strong>
    <div class="editor">
      <form id="editor">
        <label class="small muted">Title</label><br>
        <input id="pick-title" type="text" style="width:100%;padding:8px;border-radius:8px;border:1px solid #222;background:#070808;color:#e6e6e6">
        <label class="small muted" style="margin-top:8px">Short reason</label><br>
        <textarea id="pick-reason" style="width:100%;padding:8px;border-radius:8px;border:1px solid #222;background:#070808;color:#e6e6e6" rows="3"></textarea>
        <div style="margin-top:8px;display:flex;gap:8px;align-items:center">
          <button class="cta" type="submit">Save (admin)</button>
          <span class="small muted">(This is a local preview editor — in MVP we wire this to an authenticated endpoint.)</span>
        </div>
      </form>
      <div id="editor-msg" class="small muted" style="margin-top:8px"></div>
    </div>
  </div>`;
  // insert before footer
  const container = document.querySelector('.container');
  const footer = container.querySelector('footer');
  footer.insertAdjacentHTML('beforebegin', adminHtml);
  // attach handler
  const editorForm = document.getElementById('editor');
  if(editorForm) editorForm.addEventListener('submit', savePick);
  // populate from localStorage if present
  const existing = localStorage.getItem('trendcurator_pick');
  if(existing){ try{ const p = JSON.parse(existing); document.getElementById('pick-title').value = p.title; document.getElementById('pick-reason').value = p.reason;}catch(e){} }
}

// Wire Start Free and Join Pro buttons; On load, refresh latest pick and inject admin panel only if ?admin=1
window.addEventListener('DOMContentLoaded', async ()=>{ 
  // fetch /me and render badge if logged in
  try{
    const me = await fetch('/me').then(r=>r.json()).catch(()=>null);
    if(me && me.ok){
      const header = document.querySelector('header');
      const badge = document.createElement('div');
      badge.style.marginLeft='auto'; badge.style.fontSize='14px'; badge.style.color='var(--muted)'; badge.style.display='flex'; badge.style.alignItems='center'; badge.style.gap='8px';
      badge.innerHTML = `<span style="font-weight:700">${me.email}</span><span style="background:#052027;color:#cdeff3;padding:6px 8px;border-radius:8px;font-weight:700">${me.pro? 'Pro':'Free'}</span>`;
      header.appendChild(badge);
    }
  }catch(e){}

  refreshLatestPick();
  const params = new URLSearchParams(window.location.search);
  const showAdmin = params.get('admin') === '1';
  if(showAdmin) renderAdminPanel();

  // Handle Stripe redirect statuses
  const pageNoticeId = 'page-notice';
  function showPageNotice(text){
    let el = document.getElementById(pageNoticeId);
    if(!el){ el = document.createElement('div'); el.id = pageNoticeId; el.style.position='fixed'; el.style.top='12px'; el.style.right='12px'; el.style.background='#052027'; el.style.color='#cdeff3'; el.style.padding='12px 16px'; el.style.borderRadius='10px'; el.style.zIndex=9999; document.body.appendChild(el); }
    el.textContent = text;
    setTimeout(()=>{ try{ el.style.transition='opacity 0.6s'; el.style.opacity=0.95; setTimeout(()=>{ el.style.opacity=1; },100); }catch(e){} },10);
  }
  if(params.get('success')==='1'){
    showPageNotice('Payment successful — welcome to Pro (we will confirm access after webhook verification).');
  } else if(params.get('cancel')==='1'){
    showPageNotice('Checkout cancelled.');
  }

  // Start free: scroll to signup and focus
  const startBtn = document.getElementById('start-free');
  if(startBtn){ startBtn.addEventListener('click', (ev)=>{ ev.preventDefault(); const input = document.querySelector('form[action="#signup"] input[type="email"]'); input && input.scrollIntoView({behavior:'smooth',block:'center'}); input && input.focus(); }); }

  // Join Pro: open modal
  const joinPro = document.getElementById('join-pro');
  const proModal = document.getElementById('pro-modal');
  const proClose = document.getElementById('pro-close');
  const proForm = document.getElementById('pro-form');
  const proMsg = document.getElementById('pro-msg');
  if(joinPro && proModal){
    joinPro.addEventListener('click',(ev)=>{ ev.preventDefault(); proModal.style.display='flex'; const pe = document.getElementById('pro-email'); pe && pe.focus(); });
    proClose && proClose.addEventListener('click', ()=>{ proModal.style.display='none'; proMsg.textContent=''; });
    proModal.addEventListener('click',(ev)=>{ if(ev.target===proModal) { proModal.style.display='none'; proMsg.textContent=''; } });
    proForm && proForm.addEventListener('submit', async (ev)=>{
      ev.preventDefault();
      const email = document.getElementById('pro-email').value.trim();
      if(!email){ proMsg.textContent='Please enter a valid email.'; return; }
      const btn = proForm.querySelector('button'); btn.disabled=true; btn.textContent='Joining...';
      try{
        // Determine selected plan
        const planRadios = document.querySelectorAll('input[name="plan"]');
        let selectedPlan = 'yearly';
        planRadios.forEach(r=>{ if(r.checked) selectedPlan = r.value; });
        // Create Stripe Checkout session via backend and redirect
        const payload = { success_url: 'https://trendcurator.org/?success=1', cancel_url: 'https://trendcurator.org/?cancel=1', customer_email: email, plan: selectedPlan };
        const res = await fetch('/create-checkout-session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const data = await res.json().catch(()=>null);
        if(res.ok && data && data.url){
          window.location = data.url; // redirect to Stripe Checkout
          return;
        }
        // fallback to waitlist signup if checkout not available
        console.log('[PRO_SIGNUP] checkout unavailable, fallback to waitlist', res.status, data);
        const sigRes = await fetch('/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,source:'pro_waitlist',utm:''})});
        const sdata = await sigRes.json().catch(()=>null);
        if(sigRes.ok && sdata && sdata.ok){ proMsg.textContent='Thanks — you are on the Pro waitlist.'; document.getElementById('pro-email').value=''; console.log('[PRO_SIGNUP] success', sdata); sessionStorage.setItem('trendcurator_just_signed_up','1'); await refreshLatestPick(); revealAndScrollHero(); }
        else { proMsg.textContent = (sdata && sdata.error) ? sdata.error : 'Signup failed — try again later.'; }
      }catch(err){ console.error('[PRO_SIGNUP] network error', err); proMsg.textContent='Network error — try again.'; }
      finally{ btn.disabled=false; btn.textContent='Join'; }
    });
  }
});
