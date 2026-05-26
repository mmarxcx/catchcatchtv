// ==========================================
// CSRF HELPER
// ==========================================
function getCsrfToken() {
  return document.cookie.match(/csrf_token=([^;]+)/)?.[1] || '';
}

function showFeedback(okId, errId, isOk, msg) {
  const ok  = document.getElementById(okId);
  const err = document.getElementById(errId);
  if(ok) ok.classList.add('hidden');
  if(err) err.classList.add('hidden');
  if (isOk && ok) { ok.textContent = msg; ok.classList.remove('hidden'); }
  else if (err)   { err.textContent = msg; err.classList.remove('hidden'); }
}

// ==========================================
// URL VALIDATION HELPERS
// ==========================================
const GREEN = '#00a86b';
const RED   = '#d6194a';
const GRAY  = '#5a7090';

function isValidStreamUrl(val) {
  if (!val) return null; // empty = neutral (field not yet touched)
  try {
    const u = new URL(val);
    return ['http:', 'https:', 'rtsp:', 'rtmp:', 'rtmps:', 'onvif:'].includes(u.protocol) && u.hostname.length > 0;
  } catch {
    return false;
  }
}

function isValidDiscordWebhook(val) {
  if (!val) return null; // empty = neutral
  return val.startsWith('https://discord.com/api/webhooks/') ||
         val.startsWith('https://discordapp.com/api/webhooks/');
}

function applyRuleColor(el, state) {
  if (!el) return;
  el.classList.remove('met', 'unmet');
  // Clear any lingering inline styles from previous approach
  el.style.color = '';
  const icon = el.querySelector('.rule-icon');
  if (icon) { icon.style.color = ''; icon.style.borderColor = ''; icon.style.background = ''; }
  if (state === 'met') {
    el.classList.add('met');
  } else if (state === 'unmet') {
    el.classList.add('unmet');
  }
  // 'default' state: no class added — shows neutral empty circle
}

function validateStreamUrl(camId) {
  const input = document.querySelector(`.cam-url-input[data-id="${camId}"]`);
  const ruleEl = document.querySelector(`.cam-url-rule-scheme[data-id="${camId}"]`);
  if (!input || !ruleEl) return true;
  const val = input.value.trim();
  const result = isValidStreamUrl(val);
  const textEl = ruleEl.querySelector('span:last-child');
  if (result === null) {
    applyRuleColor(ruleEl, 'default');
    if (textEl) textEl.textContent = 'Example: http://192.168.x.x:8080/video, rtsp://192.168.x.x:554/stream, rtmp://192.168.x.x:1935/live, or onvif://192.168.x.x';
    return true;
  }
  applyRuleColor(ruleEl, result ? 'met' : 'unmet');
  if (textEl) textEl.textContent = result
    ? 'Valid stream URL'
    : 'Must start with http://, https://, rtsp://, rtmp://, rtmps://, or onvif:// and include a host address';
  return result;
}

function validateWebhookUrl(inputEl, ruleId) {
  const ruleEl = document.getElementById(ruleId);
  if (!inputEl || !ruleEl) return true;
  const val = inputEl.value.trim();
  const result = isValidDiscordWebhook(val);
  const textEl = ruleEl.querySelector('span:last-child');
  if (result === null) {
    applyRuleColor(ruleEl, 'default');
    if (textEl) textEl.textContent = 'Must be a valid Discord webhook URL';
    return true;
  }
  applyRuleColor(ruleEl, result ? 'met' : 'unmet');
  if (textEl) textEl.textContent = result
    ? 'Valid Discord webhook URL'
    : 'Must start with https://discord.com/api/webhooks/...';
  return result;
}

document.addEventListener('DOMContentLoaded', () => {
  // Wire up stream URL real-time validation for all existing + new cameras
  document.querySelectorAll('.cam-url-input').forEach(input => {
    const camId = input.getAttribute('data-id');
    // Initialize state for pre-filled inputs
    if (input.value.trim()) validateStreamUrl(camId);
    input.addEventListener('input', () => validateStreamUrl(camId));
  });

  // Wire up webhook URL real-time validation
  const webhookUrlInput = document.getElementById('webhookUrl');
  if (webhookUrlInput) {
    webhookUrlInput.addEventListener('input', () => validateWebhookUrl(webhookUrlInput, 'rule-webhook-url'));
  }
  const adminWebhookInput = document.getElementById('adminWebhookUrl');
  if (adminWebhookInput) {
    adminWebhookInput.addEventListener('input', () => validateWebhookUrl(adminWebhookInput, 'rule-admin-webhook-url'));
  }

  fetch('/api/account', { credentials: 'include' })
    .then(r => r.json())
    .then(d => {
      const hookUrl = document.getElementById('webhookUrl');
      if(hookUrl) {
        hookUrl.value = d.discord_webhook || '';
        if (hookUrl.value) validateWebhookUrl(hookUrl, 'rule-webhook-url');
      }
      if (d.role === 'admin') {
        const adminGrp = document.getElementById('adminWebhookGroup');
        if(adminGrp) adminGrp.style.display = 'block';
        fetch('/api/admin/webhook', { credentials: 'include' })
          .then(r => r.json())
          .then(data => {
            const adminUrl = document.getElementById('adminWebhookUrl');
            if(adminUrl) {
              adminUrl.value = data.admin_webhook || '';
              if (adminUrl.value) validateWebhookUrl(adminUrl, 'rule-admin-webhook-url');
            }
          })
          .catch(() => {
            const adminUrl = document.getElementById('adminWebhookUrl');
            if(adminUrl) adminUrl.value = '';
          });
      }
    })
    .catch(() => {});
});

// ==========================================
// BULLETPROOF EVENT MANAGER (Handles ALL buttons)
// ==========================================
document.addEventListener('click', async (e) => {

  // 1. CHANGE PASSWORD
  const changePwBtn = e.target.closest('#changePwBtn');
  if (changePwBtn) {
    const oldPw = document.getElementById('oldPw').value;
    const newPw = document.getElementById('newPw').value;
    const conf  = document.getElementById('confirmPw').value;
    if (newPw !== conf) { showFeedback('pwOk','pwErr',false,'Passwords do not match.'); return; }
    if (newPw.length < 8) { showFeedback('pwOk','pwErr',false,'Min 8 characters.'); return; }
    showFeedback('pwOk','pwErr',true,'Saving…');
    try {
      const r = await fetch('/api/account/password', {
        method:'POST', credentials:'include', headers:{'Content-Type':'application/json', 'X-CSRFToken': getCsrfToken()},
        body: JSON.stringify({old_password: oldPw, new_password: newPw})
      });
      const b = await r.json();
      if (r.ok) {
        showFeedback('pwOk','pwErr',true,'Password changed! Logging you out…');
        setTimeout(() => { window.location.href = '/logout'; }, 1500);
      } else { showFeedback('pwOk','pwErr',false,b.error||'Failed.'); }
    } catch(err) { showFeedback('pwOk','pwErr',false,'Network error. Please try again.'); }
    return;
  }

  // 2. SAVE NICKNAME
  const saveNickBtn = e.target.closest('#saveNickBtn');
  if (saveNickBtn) {
    const newNick = document.getElementById('nicknameInput').value.trim();
    if (!newNick) { showFeedback('nickOk', 'nickErr', false, 'Nickname cannot be empty.'); return; }
    if (newNick.length < 3 || newNick.length > 16) { showFeedback('nickOk', 'nickErr', false, 'Must be between 3 and 16 characters.'); return; }
    if (!/^[a-zA-Z0-9_.#]+$/.test(newNick)) { showFeedback('nickOk', 'nickErr', false, 'Only letters, numbers, and _ . # are allowed.'); return; }
    showFeedback('nickOk', 'nickErr', true, 'Saving…');
    try {
      const r = await fetch('/api/account/nickname', {
        method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken()},
        body: JSON.stringify({ nickname: newNick })
      });
      const b = await r.json();
      if (r.ok) {
        showFeedback('nickOk', 'nickErr', true, 'Nickname updated successfully!');
        document.querySelectorAll('.user-chip').forEach(el => el.textContent = newNick);
      } else { showFeedback('nickOk', 'nickErr', false, b.error || 'Failed to update nickname.'); }
    } catch (err) { showFeedback('nickOk', 'nickErr', false, 'Network error. Please try again.'); }
    return;
  }

  // 3. LOGOUT
  const logoutBtn = e.target.closest('#logoutBtn');
  if (logoutBtn) {
    window.location.href = '/logout';
    return;
  }

  // 4. MULTI-CAMERA SAVING
  const saveCamBtn = e.target.closest('.save-cam-btn');
  if (saveCamBtn) {
    const camId = saveCamBtn.getAttribute('data-id');
    const labelInput = document.querySelector(`.cam-label-input[data-id="${camId}"]`);
    const urlInput = document.querySelector(`.cam-url-input[data-id="${camId}"]`);
    const aiToggle = document.querySelector(`.cam-ai-toggle[data-id="${camId}"]`);
    const usernameInput = document.querySelector(`.cam-username-input[data-id="${camId}"]`);
    const passwordInput = document.querySelector(`.cam-password-input[data-id="${camId}"]`);

    const payload = {
      id: camId === 'new' ? null : camId,
      label: labelInput ? labelInput.value.trim() : 'My Camera',
      stream_url: urlInput ? urlInput.value.trim() : '',
      audio_url: '',
      ai_enabled: aiToggle ? aiToggle.checked : false,
      cam_username: usernameInput ? usernameInput.value.trim() : '',
      cam_password: passwordInput ? passwordInput.value.trim() : ''
    };

    // Validate stream URL before saving — block save, show inline hint (no popup)
    const isUrlValid = validateStreamUrl(camId);
    if (!isUrlValid) return;

    const originalHTML = saveCamBtn.innerHTML;
    saveCamBtn.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right: 6px;"><circle cx="12" cy="12" r="10"></circle><path d="M12 6v6l4 2"></path></svg> Saving...`;
    saveCamBtn.disabled = true;

    try {
      const r = await fetch('/api/camera', {
        method: 'POST', credentials: 'include', 
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify(payload)
      });
      const data = await r.json();
      
      if (r.ok && data.ok) {
        saveCamBtn.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right: 6px;"><polyline points="20 6 9 17 4 12"></polyline></svg> Saved!`;
        if (camId === 'new') {
          setTimeout(() => window.location.reload(), 1000);
        }
      } else {
        alert("Error: " + (data.error || "Save failed."));
        saveCamBtn.innerHTML = originalHTML;
      }
    } catch (err) {
      alert("Network error. Please try again.");
      saveCamBtn.innerHTML = originalHTML;
    }
    
    setTimeout(() => {
      saveCamBtn.disabled = false;
      if (camId !== 'new') saveCamBtn.innerHTML = originalHTML;
    }, 2000);
    return;
  }

  // 5. MULTI-CAMERA DELETE
  const deleteBtn = e.target.closest('.delete-cam-btn');
  if (deleteBtn) {
    const camId = deleteBtn.getAttribute('data-id');
    
    if (!confirm("Are you sure you want to delete this camera? This cannot be undone.")) {
      return;
    }

    const originalHTML = deleteBtn.innerHTML;
    deleteBtn.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right: 6px;"><circle cx="12" cy="12" r="10"></circle><path d="M12 6v6l4 2"></path></svg> Deleting...`;
    deleteBtn.disabled = true;

    try {
      const r = await fetch('/api/camera/delete', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
        body: JSON.stringify({ id: camId })
      });
      const data = await r.json();
      
      if (r.ok && data.ok) {
        window.location.reload();
      } else {
        alert("Error: " + (data.error || "Failed to delete camera."));
        deleteBtn.innerHTML = originalHTML;
        deleteBtn.disabled = false;
      }
    } catch (err) {
      alert("Network error. Please try again.");
      deleteBtn.innerHTML = originalHTML;
      deleteBtn.disabled = false;
    }
    return;
  }

  // 6. SAVE WEBHOOK
  const saveWebhookBtn = e.target.closest('#saveWebhookBtn');
  if (saveWebhookBtn) {
    const originalHTML = saveWebhookBtn.innerHTML;
    const errBox = document.getElementById('webhookErr');
    if (errBox) errBox.classList.add('hidden');

    // Validate webhook URLs before saving
    const webhookInput = document.getElementById('webhookUrl');
    const adminInput = document.getElementById('adminWebhookUrl');
    const userWebhookVal = webhookInput ? webhookInput.value.trim() : '';
    const adminWebhookVal = (adminInput && adminInput.offsetParent !== null) ? adminInput.value.trim() : '';

    if (userWebhookVal && !isValidDiscordWebhook(userWebhookVal)) {
      applyRuleColor(document.getElementById('rule-webhook-url'), 'unmet');
      if (errBox) { errBox.textContent = 'Invalid Discord webhook URL.'; errBox.classList.remove('hidden'); }
      return;
    }
    if (adminWebhookVal && !isValidDiscordWebhook(adminWebhookVal)) {
      applyRuleColor(document.getElementById('rule-admin-webhook-url'), 'unmet');
      if (errBox) { errBox.textContent = 'Invalid Discord admin webhook URL.'; errBox.classList.remove('hidden'); }
      return;
    }
    
    saveWebhookBtn.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right: 6px;"><circle cx="12" cy="12" r="10"></circle><path d="M12 6v6l4 2"></path></svg> Saving...`;
    saveWebhookBtn.disabled = true;

    let allOk = true, lastErr = '';
    try {
      const userUrl = document.getElementById('webhookUrl').value.trim();
      const r = await fetch('/api/account/webhook', {
        method:'POST', credentials:'include', headers:{'Content-Type':'application/json', 'X-CSRFToken': getCsrfToken()},
        body: JSON.stringify({ webhook_url: userUrl })
      });
      const b = await r.json();
      if (!r.ok) { allOk = false; lastErr = b.error || 'Failed to save webhook.'; }
    } catch(err) { allOk = false; lastErr = 'Network error. Please try again.'; }

    const adminField = document.getElementById('adminWebhookUrl');
    if (adminField && adminField.offsetParent !== null) {
      try {
        const adminUrl = adminField.value.trim();
        const r = await fetch('/api/admin/webhook', {
          method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() },
          body: JSON.stringify({ admin_webhook: adminUrl })
        });
        const b = await r.json();
        if (!r.ok) { allOk = false; lastErr = b.error || 'Failed to save admin webhook.'; }
      } catch(err) { allOk = false; lastErr = 'Network error saving admin webhook.'; }
    }
    
    if (allOk) {
      saveWebhookBtn.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right: 6px;"><polyline points="20 6 9 17 4 12"></polyline></svg> Saved!`;
      setTimeout(() => {
        saveWebhookBtn.innerHTML = originalHTML;
        saveWebhookBtn.disabled = false;
      }, 2000);
    } else {
       if (errBox) {
         errBox.textContent = lastErr;
         errBox.classList.remove('hidden');
       }
       saveWebhookBtn.innerHTML = originalHTML;
       saveWebhookBtn.disabled = false;
    }
    return;
  }

});

