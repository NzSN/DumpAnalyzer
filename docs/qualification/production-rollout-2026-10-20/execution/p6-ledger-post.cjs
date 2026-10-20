const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const {createRequire}=require('node:module');
const app='D:/Services/dump-ledger',runtime='D:/Services/dump-ledger-runtime',backup=runtime+'/backups/p6-production-20261020-verified';
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');const json=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x);
const pre=JSON.parse(fs.readFileSync(backup+'/preflight.json','utf8'));
const manifest=JSON.parse(fs.readFileSync(runtime+'/releases/p6-7c2a51b-20261020/build-manifest.json','utf8'));
for(const[name,item]of Object.entries(manifest.files)){const b=fs.readFileSync(path.join(app,name));if(hash(b)!==item.sha256||b.length!==item.bytes)throw Error('Build mismatch '+name);}
const Database=createRequire(app+'/package.json')('better-sqlite3');const db=new Database(runtime+'/data/ledger.sqlite',{readonly:true});db.defaultSafeIntegers(true);
const tables=Object.fromEntries(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(({name})=>{const rows=db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all();return[name,{rows:rows.length,sha256:hash(json(rows))}]}));
for(const[name,value]of Object.entries(pre.tables))if(name!=='schema_migrations'&&json(tables[name])!==json(value))throw Error('Existing data changed before canary '+name);
if(tables.analysis_details.rows!==0)throw Error('Unexpected publication');
if(json(db.pragma('integrity_check'))!=='[{"integrity_check":"ok"}]'||db.pragma('foreign_key_check').length)throw Error('Integrity failure');
db.close();
const script="Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'node.exe' -and $_.CommandLine -like '*p6-ledger-deploy.cjs*'} | ForEach-Object {@{pid=[int]$_.ProcessId;name=$_.Name;createdUtc=$_.CreationDate.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress}";
const wrappers=cp.execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8'}).trim().split(/\r?\n/).filter(Boolean).map(s=>JSON.parse(s));
const result={schema:'dumpanalyzer.p6.production-post-read/v1',utc:new Date().toISOString(),head:cp.execFileSync('git',['rev-parse','HEAD'],{cwd:app,encoding:'utf8'}).trim(),verifiedBuildFiles:Object.keys(manifest.files).length,tables,oldDataUnchanged:true,integrity:'ok',analysisDetails:0,configurationUnchanged:hash(fs.readFileSync(runtime+'/.env'))===pre.unchangedConfigurationSha256,deploymentWrappers:wrappers,productionReportPublications:0};
fs.writeFileSync(backup+'/post-deployment-read.json',json(result)+'\n');console.log(json(result));
