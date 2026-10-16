#!/usr/bin/env python3
"""Build the operator-installed Hangang console package from Guard's dashboard."""
from pathlib import Path
import hashlib,json,re
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'crates/guard-server/src/dashboard.html').read_text()
output=ROOT/'plugins/guard';output.mkdir(parents=True,exist_ok=True)
html=source.split('<body><main>',1)[1].split('</main>',1)[0]
html=re.sub(r'<header>.*?</header>','',html,flags=re.S)
html=re.sub(r'<p>토큰은 현재 페이지.*?</p>','<p class="guard-session-note">Hangang 관리자 인증과 권한으로 연결됩니다.</p>',html,count=1,flags=re.S)
html=html.replace('관리자 토큰을 입력해 연결하세요.','Guard에 연결 중입니다.')
(output/'panel.html').write_text('<div class="guard-console">'+html+'</div>\n')
script=source.split('<script>',1)[1].split('</script>',1)[0]
script=script.replace("'use strict';",'')
script=script.replace("let credential=''",'let credential=true')
script=script.replace('document.getElementById(id)',"root.querySelector('#'+id)").replace('document.querySelectorAll','root.querySelectorAll')
start=script.index('function connectionUI()');end=script.index('async function api(',start)
script=script[:start]+'''function connectionUI(){el('refresh').disabled=!credential||busy;root.querySelectorAll('form button,#allow-save,#allow-apply,#policy-reload,#json-apply,#json-export,#rules-load,#rules-validate,#rules-save,#lua-validate,#lua-save,#geoip-status,#geoip-reload,#update-fetch,#kubernetes-status').forEach(b=>b.disabled=!credential||busy);root.querySelectorAll('[data-lock]').forEach(b=>b.disabled=!credential||busy||b.dataset.lock==='true');policyControls();authorityControls();}\n'''+script[end:]
start=script.index('async function api(');end=script.index('async function run(',start)
script=script[:start]+'''async function api(path,method='GET',body){if((nativeAuthority===null||nativeAuthority.enabled)&&method!=='GET'&&!['kubernetes/evaluate','lookup','networks/inspect','rules/validate','update/check'].includes(path))throw Error('Kubernetes source owns this policy; manual changes are disabled.');if(!credential||disposed)throw Error('Session ended');const result=await context.api(path,{method,json:body});if(disposed)throw Error('Session ended');return result.data;}\n'''+script[end:]
start=script.index("el('connect').onclick=");end=script.index("el('refresh').onclick=",start)
script=script[:start]+script[end:]
script=script.replace("const el=id=>root.querySelector('#'+id),nf=new Intl.NumberFormat('ko-KR')", "const el=id=>root.querySelector('#'+id),nf=new Intl.NumberFormat(context.locale())")
script=script.replace("function show(text,error=false){", "function show(text,error=false){if(disposed)return;")
# Plugin presentation follows the host locale without fetching or replacing drafts.
script=script.replace("const locale=()=>document.documentElement.lang||'en';", "const locale=()=>context.locale();")
script=script.replace('fmt=n=>nf.format(Number(n)||0)', 'fmt=n=>new Intl.NumberFormat(context.locale()).format(Number(n)||0)')
script='let lastStatusAt=null,lastListsAt=null;\n'+script
start=script.index(" const status=el('native-authority-status');")
end=script.index('\nfunction connectionUI()',start)
body=script[start:end].replace(' connectionUI();\n}', '}')
script=script[:start]+" renderAuthority();connectionUI();\n}\nfunction renderAuthority(){\n if(nativeAuthority===null){el('native-authority-status').textContent=locale().startsWith('ko')?'네이티브 정책 원천 불명; 수동 변경은 비활성화됩니다.':'Native policy source unavailable; manual changes are disabled.';return;}\n"+body+script[end:]
script=script.replace("el('status-time').textContent='최근 상태 확인: '+new Date().toLocaleTimeString('ko-KR');",'lastStatusAt=Date.now();renderAges();')
script=script.replace("el('data-age').textContent='목록 갱신 '+new Date().toLocaleTimeString('ko-KR');",'lastListsAt=Date.now();renderAges();')
start=script.index('function updateCards()');end=script.index('\nasync function refreshLists()',start)
script=script[:start]+'''function renderAges(){if(lastStatusAt!==null)el('status-time').textContent=(locale().startsWith('ko')?'최근 상태 확인: ':'Status checked: ')+new Date(lastStatusAt).toLocaleTimeString(locale());if(lastListsAt!==null)el('data-age').textContent=(locale().startsWith('ko')?'목록 갱신 ':'Lists refreshed: ')+new Date(lastListsAt).toLocaleTimeString(locale());}
function updateCards(){const ko=locale().startsWith('ko'),s=lastStatus||{},c=s.capacity||{},stats=s.stats||{},mode=s.mode||savedPolicy?.mode;el('mode-card').textContent=mode==='enforce'?(ko?'집행':'Enforce'):mode==='observe'?(ko?'관찰':'Observe'):'—';el('mode-detail').textContent=savedPolicy?(savedPolicy.auto_block?(ko?'자동 IP 차단 설정됨':'Automatic IP blocking configured'):(ko?'수동 승인으로 관리':'Managed by manual approval')):(ko?'연결 전':'Connecting');el('candidate-card').textContent=c.candidates==null?'—':fmt(c.candidates);el('candidate-capacity').textContent=(ko?'최대 ':'Maximum ')+fmt(c.max_candidates);el('eligible-card').textContent=savedPolicy?fmt(tables.candidates.data.filter(row=>row.eligible).length):'—';el('block-card').textContent=c.blocks==null?'—':fmt(c.blocks);el('block-capacity').textContent=(ko?'최대 ':'Maximum ')+fmt(c.max_blocks);el('evidence-card').textContent=stats.accepted==null?'—':fmt(stats.accepted);el('drop-card').textContent=(ko?'수용량 초과 ':'Capacity dropped ')+fmt(stats.dropped_capacity)+(ko?' · 차단 거절 ':' · Block rejected ')+fmt(stats.block_capacity_rejections);}
'''+script[end:]
script=script.replace("function markDirty(){el('policy-dirty').textContent=policyDirty?'저장하지 않은 변경':'';el('allow-dirty').textContent=allowDirty?'저장하지 않은 변경':'';}","function markDirty(){const message=locale().startsWith('ko')?'저장하지 않은 변경':'Unsaved changes';el('policy-dirty').textContent=policyDirty?message:'';el('allow-dirty').textContent=allowDirty?message:'';}")
translations={'탐지 후보':'Candidates','차단 목록':'Blocks','허용 목록':'Allowlist','탐지 정책':'Detection policy','IP · CIDR 위험 조회':'IP / CIDR inspection','동적 규칙 · Lua':'Rules / Lua','GeoIP':'GeoIP','서명 업데이트':'Signed updates','상태 · 지표':'Status / metrics','운영 모드':'Mode','탐지 후보 / 수용량':'Candidates / capacity','승인 가능 후보':'Eligible candidates','차단 / 수용량':'Blocks / capacity','수집 신호 / 누락':'Signals / dropped','연결 전':'Connecting','마지막 표 갱신 기준':'At last list refresh','목록 새로고침':'Refresh lists','점수':'Score','신호 수':'Signals','최근 관측':'Last observed','위험 단계':'Risk stage','상태 · 작업':'State / action','IP 차단 승인':'Approve IP block','관찰 중':'Observing','차단 해제':'Remove block','네트워크':'Network','만료 시각':'Expires at','남은 시간':'Remaining','사유':'Reason','정책 저장':'Save policy','저장된 정책 다시 불러오기':'Reload policy','관찰 — 후보 검토만':'Observe — review candidates','집행 — 차단 적용':'Enforce — apply blocks','허니팟':'Honeypot','스캐너':'Scanner','인증 실패':'Authentication failure','잘못된 요청':'Invalid request','IP 조회':'Inspect IP','CIDR 집계':'Inspect CIDR','조회 결과':'Inspection result','폼에서 JSON 가져오기':'Export form as JSON','JSON을 폼에 적용':'Apply JSON to form','고급 JSON 편집':'Advanced JSON editor','차단 추가':'Add block','수동 차단':'Manual block','허용 초안에 추가':'Add to allowlist draft','허용 목록 저장':'Save allowlist','서명 릴리즈 검사 요청':'Check signed release','업데이트 상태 조회':'Update status','GeoIP 상태 확인':'GeoIP status','설정된 DB 다시 불러오기':'Reload configured databases','정상':'Normal','주의':'Watch','의심':'Suspicious','고위험':'High risk','차단':'Blocked','IP · 네트워크 · 사유 검색':'Search IP, network or reason','관찰':'Observe','집행':'Enforce','수동 승인으로 관리':'Managed by manual approval','오름차순':'Ascending','내림차순':'Descending','이전':'Previous','다음':'Next','등록된 항목이 없습니다.':'No entries.','검색 결과가 없습니다.':'No matching entries.','저장된 JSON 규칙 불러오기':'Load saved JSON rules','JSON 검증':'Validate JSON','JSON 규칙 저장':'Save JSON rules','Lua 검증':'Validate Lua','Lua 규칙 저장':'Save Lua rules'}
translations.update({'Kubernetes 정책 원천':'Kubernetes policy source','읽기 전용 진단입니다. 이 결과는 게이트웨이나 CNI 집행을 활성화하지 않습니다.':'Read-only diagnostics. These results do not activate gateway or CNI enforcement.','원천 상태 새로고침':'Refresh source status','원천 상태를 아직 확인하지 않았습니다.':'Source status has not been checked.','Namespace':'Namespace','Peer IP':'Peer IP','목적지 포트':'Destination port','방향':'Direction','프로토콜':'Protocol','대상 라벨 (JSON)':'Target labels (JSON)','진단 질의 평가':'Evaluate diagnostic query'})
translations.update({'품계에서 수문장 근거를 필수로 요구하는 서비스는 관찰 모드에서 접근을 허용하지 않습니다. 집행 모드의 허용 판정과 사용자·네트워크 권한이 모두 필요합니다.': 'Services requiring Sumunjang evidence in Pumgye refuse access in observe mode. An enforced allow decision and sufficient user and network permissions are required.'})
module='''// Trusted operator-installed Hangang console plugin, API contract v1.
export async function mount(context) {
 const root=context.root;let disposed=false;
 const response=await context.asset('panel.html');
 if(context.signal.aborted)return {};
 root.innerHTML=await response.text();
'''+script+'''
 const resume=()=>{if(disposed)return;clearInterval(statusTimer);statusTimer=setInterval(()=>updateStatus().catch(error=>show(error.message,true)),5000);};
 await updateStatus();await loadPolicy();await refreshLists();show('Hangang 관리자 세션으로 연결되었습니다.');resume();
 const translations=TRANSLATIONS_PLACEHOLDER;
 const reverse=Object.fromEntries(Object.entries(translations).map(([k,v])=>[v,k]));
 const translate=()=>{const dictionary=context.locale()==='en'?translations:reverse;const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let node;while(node=walker.nextNode()){if(node.parentElement.closest('textarea,pre,td.reason'))continue;const raw=node.textContent.trim();if(dictionary[raw]&&dictionary[raw]!==raw)node.textContent=node.textContent.replace(raw,dictionary[raw]);}root.querySelectorAll('[placeholder]').forEach(e=>{if(dictionary[e.placeholder]&&dictionary[e.placeholder]!==e.placeholder)e.placeholder=dictionary[e.placeholder];});};
 const presentLocale=()=>{if(disposed||context.signal.aborted)return;renderAuthority();updateCards();renderAges();markDirty();translate();};
 presentLocale();const observer=new MutationObserver(translate);observer.observe(root,{childList:true,subtree:true,characterData:true});
 const stopLocale=context.onLocaleChange?.(presentLocale)||(()=>{});
 const legacyLocaleObserver=new MutationObserver(presentLocale);if(!context.onLocaleChange)legacyLocaleObserver.observe(document.documentElement,{attributes:true,attributeFilter:['lang']});
 return {pause(){clearInterval(statusTimer);statusTimer=null;},resume,dispose(){disposed=true;credential=false;clearInterval(statusTimer);stopLocale();observer.disconnect();legacyLocaleObserver.disconnect();root.replaceChildren();}};
}
'''
module=module.replace('TRANSLATIONS_PLACEHOLDER',json.dumps(translations,ensure_ascii=False));
(output/'index.js').write_text(module)
css='''/* Use the host console's typography, theme and layout tokens. */
.guard-console{font:inherit;color:var(--text)}
.guard-console [hidden]{display:none!important}
.guard-console p,.guard-console small,.guard-console .muted{color:var(--muted)}
.guard-console .message{padding:12px 15px;background:var(--surface-2);border:1px solid var(--line);border-radius:7px;margin:12px 0;white-space:pre-wrap;overflow-wrap:anywhere}
.guard-console .message[data-error=true]{color:var(--red)}
.guard-console .cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin:20px 0}
.guard-console .card{background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:18px;min-width:0}
.guard-console .card span{display:block;color:var(--muted);font-size:11px}
.guard-console .card strong{display:block;font:600 28px var(--mono);margin:18px 0 6px}
.guard-console .panel{padding:20px;margin-top:16px}
.guard-console h2{font-size:18px;margin:0 0 12px}.guard-console h3{font-size:14px}
.guard-console .toolbar,.guard-console .actions,.guard-console .pager,.guard-console .filters{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.guard-console .toolbar{justify-content:space-between;margin:12px 0}
.guard-console nav{display:flex;gap:6px;flex-wrap:wrap}
.guard-console button{min-height:36px;padding:8px 12px;background:var(--surface-2);color:var(--text);border:1px solid var(--line);border-radius:5px;font:600 11px var(--sans);cursor:pointer}
.guard-console button[aria-selected=true],.guard-console button.primary{background:var(--cyan-soft);color:var(--cyan);border-color:var(--cyan)}
.guard-console button.danger,.guard-console .dirty{color:var(--red)}
.guard-console button:disabled{opacity:.45;cursor:default}
.guard-console input,.guard-console select,.guard-console textarea{background:var(--surface);border:1px solid var(--line-bright);color:var(--text);border-radius:5px;padding:9px 12px;font:inherit;max-width:100%}
.guard-console input:focus,.guard-console select:focus,.guard-console textarea:focus,.guard-console button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.guard-console textarea{width:100%;min-height:160px;font:12px/1.6 var(--mono);resize:vertical}
.guard-console .form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.guard-console label{display:block;color:var(--muted)}
.guard-console label input,.guard-console label select{display:block;width:100%;margin-top:5px}
.guard-console label.inline{display:flex;gap:8px;align-items:center}.guard-console label.inline input{width:auto;margin:0}
.guard-console .weights{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.guard-console .table-scroll{overflow-x:auto}.guard-console table{width:100%;border-collapse:collapse;white-space:nowrap}
.guard-console th,.guard-console td{text-align:left;padding:12px;border-bottom:1px solid var(--line);font-size:12px}
.guard-console th{color:var(--muted);background:var(--surface-2);font-size:11px}
.guard-console td.reason{white-space:normal;overflow-wrap:anywhere;max-width:360px}
.guard-console .pager{justify-content:flex-end;margin-top:15px}.guard-console .pager .count{margin-right:auto;color:var(--muted)}
.guard-console .filters input[type=search]{width:240px}.guard-console .filters select{width:auto;min-width:100px}.guard-console .empty{text-align:center;color:var(--muted);padding:30px}
.guard-console pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:14px;background:var(--surface-2);border-radius:5px;font-size:12px}
.guard-console details{margin-top:15px}.guard-console summary{cursor:pointer;color:var(--cyan)}
@media(max-width:1000px){.guard-console .cards{grid-template-columns:repeat(2,minmax(0,1fr))}.guard-console .form-grid,.guard-console .weights{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:520px){.guard-console .form-grid{grid-template-columns:1fr}.guard-console .panel{padding:14px}.guard-console .filters input[type=search]{width:100%}.guard-console .card strong{font-size:22px}}
'''
(output/'style.css').write_text(css)
routes=[('kubernetes/authority','GET',False),('kubernetes/status','GET',False),('kubernetes/evaluate','POST',False),('status','GET',False),('policy/document','GET',False),('policy/document','PUT',True),('candidates','GET',False),('candidates/approve','POST',True),('blocks','GET',False),('blocks','POST',True),('blocks','DELETE',True),('lookup','POST',False),('networks/inspect','POST',False),('rules','GET',False),('rules','PUT',True),('rules/lua','PUT',True),('rules/validate','POST',False),('geoip/reload','POST',True),('update/status','GET',False),('update/check','POST',True),('audit','GET',False),('audit/query','POST',False),('explain','POST',False),('explain/batch','POST',False),('reasons','GET',False)]
assets={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(output.iterdir()) if f.name in ['index.js','panel.html','style.css']}
manifest={'id':'guard','name':'Sumunjang (수문장)','version':'0.1.5','api_version':1,'entry':'index.js','assets':assets,'routes':[{'path':p,'method':m,'mutation':w} for p,m,w in routes]}
(output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for file in output.iterdir():
 if file.is_file(): file.chmod(0o644)
print('Guard console package built; manifest SHA-256:',hashlib.sha256((output/'manifest.json').read_bytes()).hexdigest())
