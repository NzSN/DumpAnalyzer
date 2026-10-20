const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const {createRequire}=require('node:module');const control=require('./p6-ledger-control.cjs');
const app='D:/Services/dump-ledger',runtime='D:/Services/dump-ledger-runtime',backup=runtime+'/backups/p6-production-20261020-verified';
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');const json=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x);
const proof=JSON.parse(fs.readFileSync(backup+'/canary-durability.json','utf8'));
const manifest=JSON.parse(fs.readFileSync(runtime+'/releases/p6-7c2a51b-20261020/build-manifest.json','utf8'));
const head=cp.execFileSync('git',['rev-parse','HEAD'],{cwd:app,encoding:'utf8'}).trim();if(head!==proof.candidate)throw Error('Revision changed');
for(const[name,item]of Object.entries(manifest.files)){const b=fs.readFileSync(path.join(app,name));if(hash(b)!==item.sha256||b.length!==item.bytes)throw Error('Build mismatch '+name);}
const owned=control.identity(proof.restartedIdentity.pid);if(!control.same(owned,proof.restartedIdentity))throw Error('Restarted process changed');
const Database=createRequire(app+'/package.json')('better-sqlite3');const db=new Database(runtime+'/data/ledger.sqlite',{readonly:true});db.defaultSafeIntegers(true);
const tables=Object.fromEntries(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(({name})=>{const rows=db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all();return[name,{rows:rows.length,sha256:hash(json(rows))}]}));
if(json(tables)!==json(proof.baselineTables))throw Error('Post-canary table state changed');
if(json(db.pragma('integrity_check'))!=='[{"integrity_check":"ok"}]'||db.pragma('foreign_key_check').length)throw Error('Database integrity failed');
db.close();
const script="Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'node.exe' -and $_.CommandLine -like '*p6-canary-durability.cjs*'} | ForEach-Object {[int]$_.ProcessId}";
const activeWrappers=cp.execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8'}).trim();
const original=JSON.parse(fs.readFileSync(backup+'/preflight.json','utf8'));
const result={schema:'dumpanalyzer.p6.production-canary-final/v1',utc:new Date().toISOString(),sourceHead:head,backendIdentity:owned,proxyPid:proof.listeners['4080'],tables,allPostCanaryTablesPreserved:true,verifiedBuildFiles:Object.keys(manifest.files).length,integrity:'ok',foreignKeyViolations:0,configurationUnchanged:hash(fs.readFileSync(runtime+'/.env'))===original.unchangedConfigurationSha256,activeDurabilityWrappers:activeWrappers?activeWrappers.split(/\s+/).map(Number):[],analysisId:proof.accepted.analysisId,digest:proof.accepted.digest,canonicalBytes:proof.accepted.canonicalBytes};
fs.writeFileSync(backup+'/canary-final.json',json(result)+'\n');console.log(json(result));
