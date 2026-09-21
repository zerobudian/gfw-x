// ==========================================================================
// GFW X Safe Gate — engine
// Upstream: https://budiansafe.pages.dev/app.js (BudianCloud Verify)
// Adaptations for embedding as a React pre-gate, keeping all behaviour intact:
//   1. Completion now reports through window.__SAFE_ON_COMPLETE__ instead of
//      location.assign(DESTINATION); navigation only as a final fallback.
//   2. The challenge worker URL is injected via window.__SAFE_ASSET_PATH__.worker
//      (/safe/challenge-worker.js) so it resolves post-build and in go:embed.
// Everything else (behaviour analysis, fingerprinting, FP4 model, challenge
// state machine, risk policy, ban) is unchanged from upstream.
// ==========================================================================
'use strict';
(() => {
  const DESTINATION = 'https://budiancloud.pages.dev/';
  const CLASSES = [
    { en: 'traffic lights', zh: '红绿灯', matches: [0, 4, 8] },
    { en: 'crosswalks', zh: '斑马线', matches: [1, 5, 6] },
    { en: 'cars', zh: '小轿车', matches: [2, 3, 7] }
  ];
  const I18N = {
    en: {
      heading: 'Checking your browser', intro: 'Just a moment. You’ll continue automatically.',
      headingSuccess: 'You’re all set.', introSuccess: 'Taking you to BudianCloud.',
      headingChallenge: 'One more quick check.', introChallenge: 'Complete the image challenge to continue.',
      headingError: 'We couldn’t complete the check.', introError: 'Try again, or use an image challenge.',
      headingBlocked: 'Verification unavailable.', introBlocked: 'This browser has been temporarily blocked.',
      statusBrowser: 'Checking your browser…', detailBrowser: 'This usually takes a few seconds',
      statusCompute: 'Verifying…', detailCompute: 'Please keep this page open',
      statusModel: 'Finalizing…', detailModel: 'Almost there',
      statusChallenge: 'Additional verification needed', detailChallenge: 'Select the matching images',
      statusSuccess: 'Verification complete', detailSuccess: 'Redirecting to BudianCloud',
      statusError: 'Verification interrupted', detailError: 'Try again or choose an image challenge',
      statusBlocked: 'Access temporarily blocked', detailBlocked: 'Try again in {minutes} min',
      stepBrowser: 'Browser', stepCheck: 'Verification', stepDone: 'Continue',
      useImages: 'Use an image challenge', retry: 'Try again', continueNow: 'Continue now',
      footer: 'Private browser verification', privacy: 'Privacy', help: 'Help',
      selectAll: 'Select all images with', selectHint: 'Select every match, then verify.',
      verify: 'Verify', textAlternative: 'Use a text question', imagesAlternative: 'Use images',
      noSelection: 'Select the matching images first.', wrong: 'That didn’t match. Please try again.',
      selectImage: 'Image {number}', mathPrompt: 'What is {a} + {b}?',
      invalidAnswer: 'Enter the answer and try again.',
      privacyCopy: 'The check runs locally in your browser. It uses basic browser characteristics and interaction timing. No pointer paths or fingerprint are uploaded by this page. A temporary block is stored on this device. The destination site has its own privacy practices.',
      helpCopy: 'Keep this page open until the check completes. If automatic verification fails, use the image challenge. You can switch to a text question if the images are hard to see.',
      gotIt: 'Got it', close: 'Close', newChallenge: 'New challenge', language: 'Switch to Chinese'
    },
    zh: {
      heading: '正在检查您的浏览器', intro: '请稍候，验证通过后将自动继续。',
      headingSuccess: '验证已完成', introSuccess: '即将前往 BudianCloud。',
      headingChallenge: '还需要一步验证', introChallenge: '请完成图片验证后继续。',
      headingError: '暂时无法完成验证', introError: '您可以重试，或改用图片验证。',
      headingBlocked: '暂时无法验证', introBlocked: '此浏览器已被临时限制。',
      statusBrowser: '正在检查浏览器…', detailBrowser: '通常只需几秒钟',
      statusCompute: '正在验证…', detailCompute: '请保持此页面打开',
      statusModel: '即将完成…', detailModel: '正在完成最后检查',
      statusChallenge: '需要进一步确认', detailChallenge: '请选择符合条件的图片',
      statusSuccess: '验证通过', detailSuccess: '正在跳转至 BudianCloud',
      statusError: '验证中断', detailError: '请重试，或使用图片验证',
      statusBlocked: '暂时限制访问', detailBlocked: '{minutes} 分钟后再试',
      stepBrowser: '浏览器检查', stepCheck: '安全验证', stepDone: '继续访问',
      useImages: '改用图片验证', retry: '重试', continueNow: '立即继续',
      footer: '浏览器本地验证', privacy: '隐私', help: '帮助',
      selectAll: '请选择所有包含', selectHint: '选中全部符合条件的图片，然后点击验证。',
      verify: '验证', textAlternative: '使用文字题', imagesAlternative: '使用图片',
      noSelection: '请先选择符合条件的图片。', wrong: '选择不正确，请再试一次。',
      selectImage: '图片 {number}', mathPrompt: '{a} + {b} 等于多少？',
      invalidAnswer: '请输入答案后重试。',
      privacyCopy: '验证在浏览器本地完成，使用基本浏览器特征和交互时间信息。此页面不会上传鼠标轨迹或指纹。临时限制信息保存在当前设备。目标网站有自己的隐私规则。',
      helpCopy: '验证完成前请保持页面打开。若自动验证失败，可改用图片题；图片不易辨认时可切换文字题。',
      gotIt: '知道了', close: '关闭', newChallenge: '换一组图片', language: 'Switch to English'
    }
  };
  const $ = (id) => document.getElementById(id);
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const state = { lang: /^zh\b/i.test(navigator.languages?.[0] || navigator.language || '') ? 'zh' : 'en',
    phase: 'browser', run: 0, proof: false, proofFailed: false, manual: false, solved: false,
    category: 0, order: [], selected: new Set(), textMode: false, math: null, mathEdited: false,
    wrong: 0, fingerprint: '', recentRisk: false, reason: '', started: performance.now() };
  const stats = { moves: [], actions: [], clicks: [], keys: [], scrolls: [], focus: 0,
    hidden: 0, resize: 0, totalScroll: 0, trusted: 0, total: 0, last: 0, first: performance.now() };
  const t = (key, vars = {}) => (I18N[state.lang][key] || key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? '');
  const clamp = (v, max) => Math.max(0, Math.min(1, (Number.isFinite(v) ? v : 0) / max));
  const mean = (v) => v.length ? v.reduce((a, b) => a + b, 0) / v.length : 0;
  const cv = (v) => { const a = mean(v); return a ? Math.sqrt(mean(v.map(x => (x - a) ** 2))) / a : 0; };
  const median = (v) => { if (!v.length) return 0; const a = [...v].sort((x,y) => x-y); return a[Math.floor(a.length/2)]; };
  const raf = () => new Promise(resolve => requestAnimationFrame(resolve));
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  const randomInt = (max) => crypto?.getRandomValues ? crypto.getRandomValues(new Uint32Array(1))[0] % max : Math.floor(Math.random() * max);

  function record(kind, event) {
    const now = performance.now();
    stats.total++;
    if (event?.isTrusted) stats.trusted++;
    stats.actions.push({ kind, at: now });
    if (stats.actions.length > 160) stats.actions.shift();
    stats.last = now;
    return now;
  }
  addEventListener('pointermove', e => {
    const now = performance.now();
    if (stats.moves.length && now - stats.moves.at(-1).at < 35) return;
    record('move', e);
    stats.moves.push({x:e.clientX, y:e.clientY, at:now, kind:e.pointerType});
    if (stats.moves.length > 120) stats.moves.shift();
  }, { passive:true });
  addEventListener('pointerdown', e => {
    const at = record(e.pointerType === 'touch' ? 'touch':'click', e);
    stats.clicks.push(at);
  }, { passive:true });
  addEventListener('keydown', e => {
    if (e.repeat) return;
    stats.keys.push(record('key', e));
  }, { passive:true });
  addEventListener('scroll', e => {
    stats.scrolls.push(record('scroll', e));
    stats.totalScroll += Math.abs(scrollY - (stats.previousScroll || 0)); stats.previousScroll = scrollY;
  }, { passive:true });
  addEventListener('resize', () => { stats.resize++; });
  addEventListener('blur', () => { stats.focus++; });
  document.addEventListener('visibilitychange', () => { if (document.hidden) stats.hidden++; });

  function features() {
    const moves = stats.moves, times = moves.slice(1).map((m,i) => m.at - moves[i].at);
    const distances = moves.slice(1).map((m,i) => Math.hypot(m.x-moves[i].x,m.y-moves[i].y));
    const path = distances.reduce((a,b)=>a+b,0);
    const displacement = moves.length>1 ? Math.hypot(moves.at(-1).x-moves[0].x,moves.at(-1).y-moves[0].y) : 0;
    const speeds = distances.map((d,i)=>1000*d/Math.max(times[i],1));
    let turns = 0, jitter = [];
    for(let i=2;i<moves.length;i++) {
      const a = moves[i-2],b=moves[i-1],c=moves[i];
      const angle=Math.atan2(c.y-b.y,c.x-b.x)-Math.atan2(b.y-a.y,b.x-a.x);
      const turn=Math.abs(Math.atan2(Math.sin(angle),Math.cos(angle)));
      jitter.push(turn/Math.PI); if(turn>.5)turns++;
    }
    const kinds = ['move','click','touch','key','scroll'];
    const counts = kinds.map(k=>stats.actions.filter(a=>a.kind===k).length), total=counts.reduce((a,b)=>a+b,0);
    const entropy = total ? -counts.reduce((a,n)=>{let p=n/total;return a+(p?p*Math.log2(p):0)},0)/Math.log2(5) : 0;
    const idle = stats.last ? Math.max(0, performance.now()-stats.last)/(performance.now()-stats.first+1) : 1;
    const at = stats.actions.map(a=>a.at), gaps=at.slice(1).map((x,i)=>x-at[i]);
    return new Float32Array([
      clamp((performance.now()-stats.first)/1000,12),clamp(stats.actions.length,80),clamp(moves.length,70),
      clamp(stats.clicks.length,8),clamp(stats.keys.length,12),clamp(counts[2],24),clamp(stats.scrolls.length,20),
      clamp(stats.focus,3),clamp(stats.hidden,3),clamp(path,2000),path ? Math.min(displacement/path,1):0,
      clamp(median(times),400),clamp(cv(times),3),clamp(median(speeds),2000),clamp(cv(speeds),3),
      clamp(turns,30),clamp(gaps.filter(x=>x>100&&x<500).length,30),clamp(gaps.filter(x=>x>=500).length,8),
      Math.min(idle,1),clamp(stats.totalScroll,3000),clamp(median(stats.keys.slice(1).map((v,i)=>v-stats.keys[i])),500),
      clamp(cv(stats.keys.slice(1).map((v,i)=>v-stats.keys[i])),3),
      clamp(Math.min(stats.clicks.length, moves.length),6),clamp(moves.filter(m=>m.kind==='touch').length,24),
      entropy,clamp(stats.resize,3),clamp(displacement,1200),clamp(Math.max(0,...speeds),3000),
      clamp(mean(speeds),1500),stats.total ? stats.trusted/stats.total : 0,clamp(mean(jitter),1),
      clamp(Math.max(0,...gaps),4000)
    ]);
  }

  let decoded = null;
  function modelLayers() {
    if (decoded) return decoded;
    const m = window.BUDIAN_MODEL;
    if (!m || m.format !== 'E2M1-FP4-QAT' || m.weights < 50000 || m.shape[0] !== 32 || m.shape.at(-1) !== 1) throw Error('model-unavailable');
    const mag=[0,.5,1,1.5,2,3,4,6];
    decoded=m.layers.map(layer=>{
      const bytes=Uint8Array.from(atob(layer.data),c=>c.charCodeAt(0));
      if(bytes.length*2 < layer.input*layer.output || layer.scales.length!==layer.output || layer.bias.length!==layer.output) throw Error('model-corrupt');
      const weights=new Float32Array(layer.input*layer.output);
      for(let i=0;i<weights.length;i++){
        const nibble=(i&1)?(bytes[i>>1]>>4):(bytes[i>>1]&15);
        weights[i]=(nibble&8 ? -1:1)*mag[nibble&7]*layer.scales[Math.floor(i/layer.input)];
      }
      return { input:layer.input,output:layer.output,weights,bias:layer.bias };
    });
    if(decoded.reduce((count,layer)=>count+layer.weights.length,0)!==m.weights) throw Error('model-size');
    return decoded;
  }
  function humanConfidence() {
    let a=features();
    for(const layer of modelLayers()) {
      if(a.length!==layer.input) throw Error('model-shape');
      const out=new Float32Array(layer.output);
      for(let row=0;row<layer.output;row++){
        let sum=layer.bias[row],offset=row*layer.input;
        for(let col=0;col<layer.input;col++)sum+=a[col]*layer.weights[offset+col];
        out[row]=layer.output===1?1/(1+Math.exp(-Math.max(-25,Math.min(25,sum)))):Math.max(0,sum);
      }
      a=out;
    }
    if(!Number.isFinite(a[0])) throw Error('model-output');
    return a[0];
  }
  function modelDecision() {
    try {
      const confidence=humanConfidence();
      const sample=stats.moves.length>=8 || stats.clicks.length>=2 || stats.keys.length>=2 || stats.actions.length>=12;
      if(sample && confidence<.10) return {kind:'ban',confidence};
      if(!sample) return {kind:'insufficient',confidence};
      const [slope,intercept]=window.BUDIAN_MODEL.policy;
      const odds=Math.log(Math.max(1e-5,confidence)/Math.max(1e-5,1-confidence));
      const policyChance=1/(1+Math.exp(-Math.max(-25,Math.min(25,slope*odds+intercept))));
      return {kind:confidence<.65 || policyChance>.5?'challenge':'pass',confidence};
    } catch { return {kind:'fallback',confidence:null}; }
  }

  async function browserFingerprint() {
    const input=[location.origin,navigator.userAgent,navigator.platform,navigator.vendor,
      (navigator.languages||[]).join(','),Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen.width,screen.height,screen.colorDepth,navigator.maxTouchPoints,
      navigator.hardwareConcurrency,navigator.deviceMemory].join('|');
    if(!crypto?.subtle) return 'local';
    const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(input));
    return Array.from(new Uint8Array(hash).slice(0,12),b=>b.toString(16).padStart(2,'0')).join('');
  }
  function banKey() { return 'budian-verify-ban:'+state.fingerprint; }
  function currentBan() { try { return Number(localStorage.getItem(banKey())) || 0; } catch { return state.localBan || 0; } }
  function block() {
    const until=Date.now()+10*60*1000;
    state.localBan=until;
    try { localStorage.setItem(banKey(),String(until)); } catch {}
    state.run++;setPhase('blocked');
    if($('challenge-dialog').open) $('challenge-dialog').close();
  }
  function checkBan() { if(currentBan()>Date.now()){setPhase('blocked');return true}return false; }

  function setPhase(phase) {
    state.phase=phase;
    const key=phase.charAt(0).toUpperCase()+phase.slice(1);
    const headlineKey=['browser','compute','model'].includes(phase)?'heading':`heading${key}`;
    const introKey=['browser','compute','model'].includes(phase)?'intro':`intro${key}`;
    $('heading').textContent=t(headlineKey);
    $('intro').textContent=t(introKey);
    $('status').textContent=t(`status${key}`);
    $('status-detail').textContent=t(`detail${key}`,{minutes:Math.ceil((currentBan()-Date.now())/60000)});
    const active=phase==='browser'?0:['compute','model','challenge','error','blocked'].includes(phase)?1:2;
    for(const item of $('steps').children){ const i=Number(item.dataset.step);item.className=i<active?'done':i===active?'active':''; }
    $('widget').dataset.state=['browser','compute','model'].includes(phase)?'checking':phase==='blocked'?'error':phase;
    $('progress').style.width={browser:'10%',compute:'40%',model:'82%',challenge:'82%',success:'100%',error:'35%',blocked:'35%'}[phase];
    $('widget-button').disabled=!['challenge','error'].includes(phase);
    $('image-option').hidden=['success','blocked'].includes(phase);
    $('retry').hidden=phase!=='error';
    $('continue').hidden=phase!=='success';
  }
  function setLanguage(lang) {
    state.lang=lang;document.documentElement.lang=lang==='zh'?'zh-CN':'en';
    $('language-label').textContent=lang==='zh'?'EN':'中文';
    $('language').setAttribute('aria-label',t('language'));
    for(const node of document.querySelectorAll('[data-i18n]')) node.textContent=t(node.dataset.i18n);
    $('close-challenge').setAttribute('aria-label',t('close'));
    $('close-info').setAttribute('aria-label',t('close'));
    $('refresh-challenge').setAttribute('aria-label',t('newChallenge'));
    if(state.phase) setPhase(state.phase);
    $('challenge-title').textContent=CLASSES[state.category][lang];
    for(const [i,tile] of [...$('image-grid').children].entries()) tile.setAttribute('aria-label',t('selectImage',{number:i+1}));
    if(state.math) $('math-label').textContent=t('mathPrompt',state.math);
    $('alternative').textContent=t(state.textMode?'imagesAlternative':'textAlternative');
    if($('info-dialog').open) showInfo(state.reason);
  }
  $('language').addEventListener('click',()=>setLanguage(state.lang==='zh'?'en':'zh'));
  addEventListener('languagechange',()=>setLanguage(/^zh\b/i.test(navigator.languages?.[0]||navigator.language||'')?'zh':'en'));
  function showInfo(which) {
    state.reason=which;
    $('info-title').textContent=t(which);
    $('info-copy').textContent=t(which+'Copy');
    if(!$('info-dialog').open) $('info-dialog').showModal();
  }
  $('privacy').addEventListener('click',()=>showInfo('privacy'));
  $('help').addEventListener('click',()=>showInfo('help'));
  $('close-info').addEventListener('click',()=>$('info-dialog').close());
  $('info-done').addEventListener('click',()=>$('info-dialog').close());

  function shuffle(array) {
    for(let i=array.length-1;i>0;i--){ const j=randomInt(i+1);[array[i],array[j]]=[array[j],array[i]]; }
    return array;
  }
  function freshChallenge() {
    state.category=randomInt(CLASSES.length);
    state.order=shuffle([0,1,2,3,4,5,6,7,8]);
    state.selected.clear();state.wrong=0;state.math={a:4+randomInt(15),b:3+randomInt(16)};
    state.mathEdited=false;
    $('math-answer').value='';$('challenge-error').textContent='';
    $('challenge-title').textContent=CLASSES[state.category][state.lang];
    $('math-label').textContent=t('mathPrompt',state.math);
    const grid=$('image-grid');grid.replaceChildren();
    for(let i=0;i<9;i++){
      const tile=document.createElement('button');tile.type='button';tile.className='image-tile';
      tile.setAttribute('aria-pressed','false');tile.setAttribute('aria-label',t('selectImage',{number:i+1}));
      tile.dataset.source=String(state.order[i]);
      const image=document.createElement('span');image.className='tile-image tile-'+state.order[i];
      tile.append(image);
      tile.addEventListener('click',e=>{
        if(!e.isTrusted || checkBan()) return;
        const id=Number(tile.dataset.source);
        if(state.selected.has(id))state.selected.delete(id);else state.selected.add(id);
        tile.setAttribute('aria-pressed',String(state.selected.has(id)));
        $('challenge-error').textContent='';
        if(modelDecision().kind==='ban')block();
      });
      grid.append(tile);
    }
  }
  function openChallenge() {
    if(checkBan())return;
    state.manual=true;
    if(!state.order.length)freshChallenge();
    setPhase('challenge');
    if(!$('challenge-dialog').open)$('challenge-dialog').showModal();
  }
  $('image-option').addEventListener('click',e=>{if(e.isTrusted)openChallenge()});
  $('widget-button').addEventListener('click',e=>{
    if(!e.isTrusted)return;
    if(state.phase==='challenge')openChallenge(); else if(state.phase==='error')startRun();
  });
  $('close-challenge').addEventListener('click',()=>$('challenge-dialog').close());
  $('challenge-dialog').addEventListener('close',()=>{if(state.phase==='challenge')$('widget-button').focus()});
  $('refresh-challenge').addEventListener('click',e=>{if(e.isTrusted)freshChallenge()});
  $('alternative').addEventListener('click',e=>{
    if(!e.isTrusted)return;
    state.textMode=!state.textMode;
    $('image-grid').hidden=state.textMode;$('text-challenge').hidden=!state.textMode;
    $('alternative').textContent=t(state.textMode?'imagesAlternative':'textAlternative');
    $('challenge-error').textContent='';
    if(state.textMode)$('math-answer').focus();
  });
  $('math-answer').addEventListener('input',e=>{if(e.isTrusted)state.mathEdited=true});
  $('math-answer').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();verifySelection(e)}});

  function verifySelection(event) {
    if(!event.isTrusted || checkBan())return;
    const assessment=modelDecision();
    if(assessment.kind==='ban'){block();return;}
    let correct;
    if(state.textMode){
      if(!state.mathEdited || !/^\d{1,3}$/.test($('math-answer').value.trim())){
        $('challenge-error').textContent=t('invalidAnswer');return;
      }
      correct=Number($('math-answer').value)===state.math.a+state.math.b;
    } else {
      if(!state.selected.size){$('challenge-error').textContent=t('noSelection');return;}
      const matches=CLASSES[state.category].matches;
      correct=matches.length===state.selected.size && matches.every(id=>state.selected.has(id));
    }
    if(!correct){
      state.wrong++;
      $('challenge-error').textContent=t('wrong');
      if(state.wrong>=3){freshChallenge();$('challenge-error').textContent=t('wrong');}
      return;
    }
    // Rerun the model after challenge interactions; model failure keeps the
    // successful challenge as the accessible fallback.
    if(modelDecision().kind==='ban'){block();return;}
    state.solved=true;$('challenge-dialog').close();
    if(state.proof || state.proofFailed)complete();
    else setPhase('model');
  }
  $('verify-selection').addEventListener('click',verifySelection);
  $('retry').addEventListener('click',e=>{if(e.isTrusted)startRun()});

  async function delayVisible(ms,run) {
    let left=ms, last=performance.now();
    while(left>0&&run===state.run){await sleep(Math.min(left,110));const now=performance.now();if(!document.hidden)left-=Math.min(now-last,150);last=now;}
  }
  function zeroBits(bytes,bits){
    const whole=bits>>3,rest=bits&7;
    for(let i=0;i<whole;i++)if(bytes[i]!==0)return false;
    return !rest || (bytes[whole]>>>(8-rest))===0;
  }
  async function solveProof(bits=12){
    if(!crypto?.subtle||!crypto.getRandomValues||!window.Worker)throw Error('unsupported');
    const nonce=Array.from(crypto.getRandomValues(new Uint8Array(24)),b=>b.toString(16).padStart(2,'0')).join('');
    const worker=new Worker(typeof __SAFE_ASSET_PATH__ !== 'undefined' ? __SAFE_ASSET_PATH__.worker : 'challenge-worker.js');
    try {
      const result=await new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(Error('timeout')),18000);
        worker.onmessage=e=>{clearTimeout(timer);e.data.error?reject(Error(e.data.error)):resolve(e.data.counter)};
        worker.onerror=()=>{clearTimeout(timer);reject(Error('worker-failed'))};
        worker.postMessage({nonce,bits,budgetMs:15000});
      });
      if(!Number.isSafeInteger(result)||result<0)throw Error('bad-proof');
      const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(nonce+':'+result)));
      if(!zeroBits(bytes,bits))throw Error('bad-proof');
      return true;
    } finally {worker.terminate();}
  }
  async function complete() {
    if(checkBan())return;
    if(state.manual&&!state.solved){openChallenge();return;}
    setPhase('success');
    const run=state.run;
    await delayVisible(reduced.matches?900:1600,run);
    if(run===state.run&&!checkBan()&&state.phase==='success'){
      if(typeof __SAFE_ON_COMPLETE__ === 'function'){ __SAFE_ON_COMPLETE__(); return; }
      location.assign(DESTINATION);
    }
  }
  async function startRun() {
    if(checkBan())return;
    const run=++state.run;
    state.proof=false;state.proofFailed=false;state.solved=false;state.manual=false;state.order=[];
    const start=performance.now();setPhase('browser');
    try {
      await delayVisible(1500,run);if(run!==state.run)return;
      const headless=!!navigator.webdriver || /HeadlessChrome|PhantomJS|puppeteer|playwright/i.test(navigator.userAgent);
      const anomaly=screen.width<=0 || !navigator.userAgent || !(navigator.languages||[]).length;
      const trap=$('website').value.length>0;
      state.manual=headless||anomaly||trap||state.recentRisk;
      setPhase('compute');
      const proofTask=solveProof(12).then(()=>true,()=>false);
      await delayVisible(2500,run);if(run!==state.run)return;
      const proof=await proofTask;if(run!==state.run)return;
      state.proof=proof;state.proofFailed=!proof;
      setPhase('model');
      await delayVisible(700,run);if(run!==state.run)return;
      const verdict=modelDecision();
      if(verdict.kind==='ban'){block();return;}
      if(!proof || verdict.kind==='fallback' || verdict.kind==='challenge')state.manual=true;
      if(state.manual&&!state.solved){openChallenge();return;}
      await delayVisible(Math.max(0,7900-(performance.now()-start)),run);
      if(run===state.run)complete();
    } catch {
      if(run===state.run){state.proofFailed=true;openChallenge();}
    }
  }
  async function initialize() {
    setLanguage(state.lang);
    state.fingerprint=await browserFingerprint().catch(()=> 'local');
    if(checkBan())return;
    try {
      const key='budian-verify-attempts:'+state.fingerprint;
      const recent=JSON.parse(sessionStorage.getItem(key)||'[]').filter(v=>Number.isFinite(v)&&Date.now()-v<5*60*1000);
      state.recentRisk=recent.length>=3;
      sessionStorage.setItem(key,JSON.stringify([...recent,Date.now()]));
    } catch {}
    await raf();
    startRun();
  }
  initialize();
})();
