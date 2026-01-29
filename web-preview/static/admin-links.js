async function api(path, opts={}){
  const token = sessionStorage.getItem('tc_admin_token');
  const headers = opts.headers || {};
  if(token) headers['X-Admin-Token'] = token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if(res.status===401){ document.getElementById('status').textContent='Unauthorized — invalid admin token'; }
  return res.json().catch(()=>({ ok:false, status: res.status }));
}

async function loadLinks(){
  const data = await api('/admin/api/links');
  const tbody = document.querySelector('#links-table tbody'); tbody.innerHTML='';
  if(!data || !Array.isArray(data)) return;
  data.forEach(row=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${row.slug}</td>
      <td><input data-slug="${row.slug}" data-field="default_url" value="${row.default_url||''}"></td>
      <td><input data-slug="${row.slug}" data-field="affiliate_url" value="${row.affiliate_url||''}"></td>
      <td><input data-slug="${row.slug}" data-field="url_uk" value="${row.url_uk||''}"></td>
      <td><input data-slug="${row.slug}" data-field="url_us" value="${row.url_us||''}"></td>
      <td><input data-slug="${row.slug}" data-field="url_eu" value="${row.url_eu||''}"></td>
      <td><input data-slug="${row.slug}" data-field="url_row" value="${row.url_row||''}"></td>
      <td>${(row.issues||[]).map(i=>`<a href="/archive.html#${i.id}" target="_blank">${i.title}</a>`).join('<br>')}</td>
      <td><button class="save" data-slug="${row.slug}">Save</button> <button class="del" data-slug="${row.slug}">Delete</button> <button class="clicks" data-slug="${row.slug}">Clicks</button></td>`;
    tbody.appendChild(tr);
  });
  document.querySelectorAll('button.save').forEach(b=>b.addEventListener('click', async (ev)=>{
    const slug = ev.target.dataset.slug; const inputs = document.querySelectorAll(`input[data-slug='${slug}']`);
    const payload = { slug };
    inputs.forEach(inp=>{ payload[inp.dataset.field] = inp.value.trim()||null; });
    const res = await api(`/admin/api/links/${slug}`, { method: 'PUT', body: JSON.stringify(payload) });
    document.getElementById('status').textContent = JSON.stringify(res);
    loadLinks();
  }));
  document.querySelectorAll('button.del').forEach(b=>b.addEventListener('click', async (ev)=>{
    const slug = ev.target.dataset.slug;
    if(!confirm('Delete link '+slug+'?')) return;
    const res = await api(`/admin/api/links/${slug}`, { method: 'DELETE' });
    document.getElementById('status').textContent = JSON.stringify(res);
    loadLinks();
  }));
}

document.getElementById('save-token').addEventListener('click', ()=>{
  const t = document.getElementById('admin-token').value.trim(); if(!t) return; sessionStorage.setItem('tc_admin_token', t); document.getElementById('status').textContent='Token saved in sessionStorage';
  loadLinks();
});

document.getElementById('new-link-form').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const payload = { slug: document.getElementById('new-slug').value.trim(), default_url: document.getElementById('new-default').value.trim(), url_uk: document.getElementById('new-uk').value.trim()||null, url_us: document.getElementById('new-us').value.trim()||null, url_eu: document.getElementById('new-eu').value.trim()||null, url_row: document.getElementById('new-row').value.trim()||null };
  const res = await api('/admin/api/links', { method: 'POST', body: JSON.stringify(payload) });
  document.getElementById('status').textContent = JSON.stringify(res);
  loadLinks();
});

// auto-load if token present
if(sessionStorage.getItem('tc_admin_token')){ loadLinks(); }
