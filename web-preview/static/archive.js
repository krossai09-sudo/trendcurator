async function load(){
  try{
    const res = await fetch('/issues');
    const issues = await res.json();
    const list = document.getElementById('list');
    if(!issues.length){ list.innerHTML = '<p class="muted">No issues published yet.</p>'; return; }
    list.innerHTML = '';
    issues.forEach(i=>{
      const d = new Date(i.ts);
      const el = document.createElement('div'); el.className='item';
      el.innerHTML = `<div style="display:flex;justify-content:space-between"><a href="${i.link||'#'}" target="_blank" rel="noopener noreferrer">${i.title}</a><div class="muted">${d.toLocaleString()}</div></div><div class="muted" style="margin-top:8px">${i.reason}</div>`;
      list.appendChild(el);
    });
  }catch(e){ document.getElementById('list').innerHTML = '<p class="muted">Failed to load archive.</p>'; }
}
load();