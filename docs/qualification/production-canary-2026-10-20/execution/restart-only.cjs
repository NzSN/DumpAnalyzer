const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const {createRequire}=require('node:module');const control=require('./p6-ledger-control.cjs');
const app='D:/Services/dump-ledger',runtime='D:/Services/dump-ledger-runtime';
const backup=runtime+'/backups/p6-production-20261020-verified';
const analysisId='analysis_06F9B90BAB5F449199FA9C9C93',dumpId='dump_4142A5B57E5A4C01A1C47C883E';
const digest='d2ed241e0b7b36f0b6b4bf8cc355673ac910399ffb7cd90488f08fe27a85f2cb';
const Database=createRequire(app+'/package.json')('better-sqlite3');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');const json=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x);
const open=p=>{const db=new Database(p,{readonly:true,fileMustExist:true});db.defaultSafeIntegers(true);return db};
const snapshot=db=>Object.fromEntries(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(({name})=>{const rows=db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all();return[name,{rows:rows.length,sha256:hash(json(rows))}]}));
function verifyDatabase(db){
 if(json(db.pragma('integrity_check'))!=='[{"integrity_check":"ok"}]'||db.pragma('foreign_key_check').length)throw Error('Database integrity failed');
 const versions=db.prepare('SELECT version FROM schema_migrations ORDER BY version').all().map(x=>Number(x.version));
 if(json(versions)!==json([1,2,3,4,5,6,7,8,9,10]))throw Error('Migration mismatch');
 const detail=db.prepare('SELECT report_digest,report_json FROM analysis_details WHERE analysis_id=?').get(analysisId);
 if(!detail||detail.report_digest!==digest||hash(detail.report_json)!==digest||Buffer.byteLength(detail.report_json)!==63438)throw Error('Approved canonical detail changed or missing');
 const row=db.prepare('SELECT dump_id FROM dump_analyses WHERE analysis_id=?').get(analysisId);
 if(row?.dump_id!==dumpId)throw Error('Approved analysis locator changed');
 return {analysisId,dumpId,canonicalBytes:63438,digest};
}
function listeners(){const result={};for(const l of cp.execFileSync('netstat',['-ano'],{encoding:'utf8'}).split(/\r?\n/)){const p=l.trim().split(/\s+/);const m=p[1]?.match(/:(408[012])$/);if(p[0]==='TCP'&&p[3]==='LISTENING'&&m){if(result[m[1]]&&result[m[1]]!==Number(p[4]))throw Error('Multiple listener owners');result[m[1]]=Number(p[4]);}}return result;}
function start(label){
 const file=backup+'/launch-'+label+'.json';
 cp.execFileSync('bash',['-lc','/d/Services/dump-ledger-runtime/tmp/p6-start-ledger-backend-20261020.sh '+file],{encoding:'utf8'});
 const record=JSON.parse(fs.readFileSync(file,'utf8'));if(!record.nativeIdentity?.isBackend)throw Error('No native launch identity');return record.nativeIdentity;
}
async function healthy(owned){for(let i=0;i<80;i++){try{const response=await fetch('http://127.0.0.1:4081/health',{signal:AbortSignal.timeout(1000)});await response.arrayBuffer();if(response.status===200){const p=listeners();if(p['4081']===owned.pid&&p['4082']===owned.pid&&control.same(control.identity(owned.pid),owned))return p;}}catch{}await new Promise(r=>setTimeout(r,500));}throw Error('Tracked restarted backend did not become healthy');}
async function terminateFailedLaunch(owned,label){
 if(owned)return control.stop(owned);
 const file=backup+'/launch-'+label+'.json';if(!fs.existsSync(file))return {notLaunched:true};
 let receipt;try{receipt=JSON.parse(fs.readFileSync(file,'utf8'))}catch{throw Error('Uncertain launch receipt; recovery refused')}
 if(receipt.nativeIdentity)return control.stop(receipt.nativeIdentity);
 if(receipt.childExitConfirmed!==true)throw Error('Uncertain child exit; recovery refused');return {exitConfirmed:true};
}
(async()=>{
 const candidate='7c2a51b51d2638c462778c17fe9421632297b236';
 if(cp.execFileSync('git',['rev-parse','HEAD'],{cwd:app,encoding:'utf8'}).trim()!==candidate)throw Error('Deployed revision changed');
 const pre=JSON.parse(fs.readFileSync(backup+'/preflight.json','utf8'));
 const deployment=JSON.parse(fs.readFileSync(backup+'/deployment.json','utf8'));
 if(hash(fs.readFileSync(runtime+'/.env'))!==pre.unchangedConfigurationSha256)throw Error('Configuration changed');
 const manifest=JSON.parse(fs.readFileSync(runtime+'/releases/p6-7c2a51b-20261020/build-manifest.json','utf8'));
 for(const[name,item]of Object.entries(manifest.files)){const b=fs.readFileSync(path.join(app,name));if(hash(b)!==item.sha256||b.length!==item.bytes)throw Error('Build mismatch '+name);}
 for(const n of ['launch-durability.json','launch-durability-recovery.json','post-canary-online.sqlite','post-canary-stopped.sqlite','canary-durability.json'])if(fs.existsSync(backup+'/'+n))throw Error('Exclusive durability checkpoint exists; review before retry');
 const initial=listeners();const owned=control.identity(deployment.launchedIdentity.pid);
 if(!control.same(owned,deployment.launchedIdentity)||!owned.isBackend||initial['4081']!==owned.pid||initial['4082']!==owned.pid||initial['4080']!==deployment.listeners['4080'])throw Error('Current process ownership changed');
 const db=open(runtime+'/data/ledger.sqlite');const accepted=verifyDatabase(db);
 if(db.prepare("SELECT COUNT(*) AS n FROM dumps WHERE phase NOT IN ('available','rejected','deleted')").get().n!==0n)throw Error('Intake/purge is active; postpone restart');
 const original=open(backup+'/online-before.sqlite');const originalTables=snapshot(original);
 const preserved={};
 for(const name of Object.keys(originalTables)){
  if(name==='schema_migrations')continue;
  const rows=original.prepare(`SELECT rowid AS p6_rowid,* FROM "${name}" ORDER BY rowid`).all();const read=db.prepare(`SELECT rowid AS p6_rowid,* FROM "${name}" WHERE rowid=?`);
  for(const row of rows)if(json(read.get(row.p6_rowid))!==json(row))throw Error('Pre-canary row changed in '+name);
  const count=Number(db.prepare(`SELECT COUNT(*) AS n FROM "${name}"`).get().n);
  const expected=rows.length+(['audit_events','dump_analyses'].includes(name)?1:0);if(count!==expected)throw Error('Unrelated row addition/removal in '+name);
  preserved[name]=rows.length;
 }
 original.close();
 const baseline=snapshot(db);if(baseline.analysis_details.rows!==1)throw Error('Unexpected detail count');
 const added=db.prepare('SELECT action,dump_id FROM audit_events WHERE rowid>(SELECT MAX(rowid) FROM audit_events)-1').get();
 if(added?.action!=='RecordAnalysis'||added.dump_id!==dumpId)throw Error('Unexpected canary audit event');
 await db.backup(backup+'/post-canary-online.sqlite');db.close();
 const saved=open(backup+'/post-canary-online.sqlite');if(json(snapshot(saved))!==json(baseline))throw Error('Post-canary online backup differs');verifyDatabase(saved);saved.close();
 const event={schema:'dumpanalyzer.p6.production-canary-durability/v1',startedUtc:new Date().toISOString(),candidate,accepted,initialListeners:initial,initialIdentity:owned,preCanaryRowsPreserved:preserved,allowedAdditions:{dump_analyses:1,analysis_details:1,audit_events:1},baselineTables:baseline,postCanaryOnlineBackup:backup+'/post-canary-online.sqlite',buildFilesVerified:Object.keys(manifest.files).length,databaseRestorePerformed:false};
 let stopAttempted=false,stopped=false,launched=null;
 try{
  stopAttempted=true;event.initialStop=await control.stop(owned);stopped=true;
  const quiet=open(runtime+'/data/ledger.sqlite');if(json(snapshot(quiet))!==json(baseline))throw Error('Database changed before stopped-state checkpoint');await quiet.backup(backup+'/post-canary-stopped.sqlite');quiet.close();
  launched=start('durability');event.restartedIdentity=launched;const current=await healthy(launched);
  if(current['4080']!==initial['4080'])throw Error('Proxy changed');
  const reopened=open(runtime+'/data/ledger.sqlite');verifyDatabase(reopened);const after=snapshot(reopened);
  if(json(after)!==json(baseline))throw Error('Post-canary data changed across restart');reopened.close();
  if(hash(fs.readFileSync(runtime+'/.env'))!==pre.unchangedConfigurationSha256)throw Error('Configuration changed');
  Object.assign(event,{status:'passed',finishedUtc:new Date().toISOString(),listeners:current,allPostCanaryTablesPreserved:true,canonicalDetailSurvivedRestart:true,integrity:'ok',foreignKeyViolations:0,configurationUnchanged:true,proxyPreserved:true,postCanaryStoppedBackup:backup+'/post-canary-stopped.sqlite'});
  fs.writeFileSync(backup+'/canary-durability.json',json(event)+'\n');console.log(json(event));
 }catch(e){
  event.status='failed';event.error=e.message;
  if(stopAttempted){try{if(!stopped)event.initialStopReconfirmed=await control.stop(owned);event.failedProcessStop=await terminateFailedLaunch(launched,'durability');const p=listeners();if(p['4081']||p['4082'])throw Error('Unexpected listener; recovery refused');const recovery=start('durability-recovery');event.recoveryIdentity=recovery;event.recoveryListeners=await healthy(recovery);event.recovery='Same tested build and current database; no old database restored';}catch(recovery){event.recoveryError=recovery.message;}}
  fs.writeFileSync(backup+'/canary-durability-failed.json',json(event)+'\n');throw Error(json(event));
 }
})().catch(e=>{console.error(e.message);process.exitCode=1});
