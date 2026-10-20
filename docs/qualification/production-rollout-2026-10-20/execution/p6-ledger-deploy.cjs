const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const {createRequire}=require('node:module');
const control=require('./p6-ledger-control.cjs');
const app='D:/Services/dump-ledger',runtime='D:/Services/dump-ledger-runtime';
const backup=runtime+'/backups/p6-production-20261020-verified';
const release=runtime+'/releases/p6-7c2a51b-20261020';
const old='69eb3d3ad177421f8b28697ca5e9a95254c68530',candidate='7c2a51b51d2638c462778c17fe9421632297b236';
const Database=createRequire(app+'/package.json')('better-sqlite3');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const json=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x);
const git=args=>cp.execFileSync('git',args,{cwd:app,encoding:'utf8'}).trim();
const snapshot=db=>Object.fromEntries(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(({name})=>{const rows=db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all();return[name,{rows:rows.length,sha256:hash(json(rows))}]}));
function listeners(){
 const lines=cp.execFileSync('netstat',['-ano'],{encoding:'utf8'}).split(/\r?\n/);const result={};
 for(const line of lines){const p=line.trim().split(/\s+/);if(p[0]==='TCP'&&p[3]==='LISTENING'){const m=p[1].match(/:(408[012])$/);if(m){if(result[m[1]]&&result[m[1]]!==Number(p[4]))throw Error('Multiple listener owners');result[m[1]]=Number(p[4]);}}}
 return result;
}
function startBackend(label){
 const record=backup+'/launch-'+label+'.json';
 cp.execFileSync('bash',['-lc','/d/Services/dump-ledger-runtime/tmp/p6-start-ledger-backend-20261020.sh '+record],{encoding:'utf8'});
 const launch=JSON.parse(fs.readFileSync(record,'utf8'));
 if(!launch.nativeIdentity?.isBackend)throw Error('No tracked native backend identity');
 return launch.nativeIdentity;
}
async function healthy(owned){for(let i=0;i<80;i++){try{const r=await fetch('http://127.0.0.1:4081/health',{signal:AbortSignal.timeout(1000)});if(r.status===200){const p=listeners();if(p['4081']===owned.pid&&p['4082']===owned.pid&&control.same(control.identity(owned.pid),owned))return p;}}catch{}await new Promise(r=>setTimeout(r,500));}throw Error('Tracked backend failed to become healthy');}
function verifyBuild(root,manifest){for(const[name,item]of Object.entries(manifest.files)){const data=fs.readFileSync(path.join(root,name));if(data.length!==item.bytes||hash(data)!==item.sha256)throw Error('Build mismatch '+name);}}
(async()=>{
 const preflight=JSON.parse(fs.readFileSync(backup+'/preflight.json','utf8'));
 const proof=JSON.parse(fs.readFileSync(backup+'/migration-proof.json','utf8'));
 const manifest=JSON.parse(fs.readFileSync(release+'/build-manifest.json','utf8'));
 if(['candidate','rollback'].some(label=>fs.existsSync(backup+'/launch-'+label+'.json')))throw Error('Launch receipt exists; prepare a new reviewed attempt before stopping production');
 if(git(['rev-parse','HEAD'])!==old||proof.sourceCommit!==candidate||manifest.sourceCommit!==candidate)throw Error('Revision guard failed');
 git(['merge-base','--is-ancestor',old,candidate]);
 if(git(['status','--porcelain'])!=='?? .msf-diag.mjs')throw Error('Production source changed');
 if(hash(fs.readFileSync(runtime+'/.env'))!==preflight.unchangedConfigurationSha256)throw Error('Production configuration changed');
 verifyBuild(release,manifest);
 const diagHash=hash(fs.readFileSync(app+'/.msf-diag.mjs'));
 const initial=listeners();if(initial['4081']!==50512||initial['4082']!==50512||initial['4080']!==63648)throw Error('Listener identity changed since inventory');
 const initialIdentity=control.identity(initial['4081']);if(!initialIdentity?.isBackend)throw Error('Initial listener is not owned backend');
 const db=new Database(runtime+'/data/ledger.sqlite',{readonly:true});db.defaultSafeIntegers(true);
 if(db.prepare("SELECT COUNT(*) AS n FROM dumps WHERE phase NOT IN ('available','rejected','deleted')").get().n!==0n)throw Error('Active intake or purge present; do not interrupt');
 const live=snapshot(db);if(json(live)!==json(preflight.tables))throw Error('Production data changed since backup; refresh checkpoint first');
 db.close();
 const events={schema:'dumpanalyzer.p6.production-deployment/v1',startedUtc:new Date().toISOString(),beforeHead:old,candidate,initialListeners:initial,initialBackendIdentity:initialIdentity,termination:'Targeted Windows taskkill /F with native creation identity and confirmed exit after verified quiet intake and online backup; stopped-state backup follows.',configurationUnchanged:true};
 let stopped=false,sourceAdvanced=false,distSwapped=false,contractsSwapped=false,launched=null;
 try{
  await control.stop(initialIdentity);stopped=true;
  const stoppedDb=new Database(runtime+'/data/ledger.sqlite',{readonly:true});stoppedDb.defaultSafeIntegers(true);
  await stoppedDb.backup(backup+'/stopped-before.sqlite');
  const stoppedTables=snapshot(stoppedDb);stoppedDb.close();
  if(json(stoppedTables)!==json(preflight.tables))throw Error('Stopped-state data differed; preserve checkpoint and review');
  git(['merge','--ff-only',candidate]);sourceAdvanced=true;
  fs.renameSync(app+'/dist',backup+'/dist-at-swap');distSwapped=true;
  fs.cpSync(release+'/dist',app+'/dist',{recursive:true});
  fs.renameSync(app+'/packages/http-contracts/dist',backup+'/contracts-dist-at-swap');contractsSwapped=true;
  fs.cpSync(release+'/packages/http-contracts/dist',app+'/packages/http-contracts/dist',{recursive:true});
  verifyBuild(app,manifest);
  launched=startBackend('candidate');events.launchedIdentity=launched;const current=await healthy(launched);
  if(current['4080']!==initial['4080'])throw Error('Proxy process changed');
  if(hash(fs.readFileSync(runtime+'/.env'))!==preflight.unchangedConfigurationSha256)throw Error('Configuration changed');
  if(hash(fs.readFileSync(app+'/.msf-diag.mjs'))!==diagHash)throw Error('Unrelated file changed');
  if(git(['status','--porcelain'])!=='?? .msf-diag.mjs')throw Error('Unexpected tracked or untracked changes');
  const afterDb=new Database(runtime+'/data/ledger.sqlite',{readonly:true});afterDb.defaultSafeIntegers(true);const after=snapshot(afterDb);
  for(const[name,value]of Object.entries(preflight.tables))if(name!=='schema_migrations'&&json(after[name])!==json(value))throw Error('Old data changed '+name);
  const versions=afterDb.prepare('SELECT version FROM schema_migrations ORDER BY version').all().map(x=>Number(x.version));
  if(json(versions)!==json([1,2,3,4,5,6,7,8,9,10])||after.analysis_details?.rows!==0)throw Error('Live migration result differs');
  if(json(afterDb.pragma('integrity_check'))!=='[{"integrity_check":"ok"}]'||afterDb.pragma('foreign_key_check').length)throw Error('Live database integrity failed');
  afterDb.close();
  Object.assign(events,{status:'deployed',finishedUtc:new Date().toISOString(),afterHead:git(['rev-parse','HEAD']),listeners:current,buildFilesVerified:Object.keys(manifest.files).length,migrations:versions,tables:after,oldTablesPreserved:true,integrity:'ok',unrelatedFilePreserved:true,proxyPreserved:true});
  fs.writeFileSync(backup+'/deployment.json',json(events)+'\n');console.log(json(events));
 }catch(e){
  events.error=e.message;events.status='failed';
  if(stopped){
   try{
    if(launched)events.failedCandidateStop=await control.stop(launched);
    else if(fs.existsSync(backup+'/launch-candidate.json')){
     let failed;try{failed=JSON.parse(fs.readFileSync(backup+'/launch-candidate.json','utf8'))}catch{throw Error('Uncertain candidate launch; refusing rollback swap')}
     if(failed.nativeIdentity)events.failedCandidateStop=await control.stop(failed.nativeIdentity);
     else if(failed.childExitConfirmed!==true)throw Error('Candidate exit not confirmed; refusing rollback swap');
    }
    const active=listeners();if(active['4081']||active['4082'])throw Error('Unexpected live backend prevents rollback swap');
    if(distSwapped){fs.rmSync(app+'/dist',{recursive:true,force:true});fs.renameSync(backup+'/dist-at-swap',app+'/dist');}
    if(contractsSwapped){fs.rmSync(app+'/packages/http-contracts/dist',{recursive:true,force:true});fs.renameSync(backup+'/contracts-dist-at-swap',app+'/packages/http-contracts/dist');}
    if(sourceAdvanced)git(['reset','--keep',old]);
    const rollbackIdentity=startBackend('rollback');events.rollbackIdentity=rollbackIdentity;events.rollbackListeners=await healthy(rollbackIdentity);events.rollback='previous code/build restored; additive database retained; no production canary was published';
   }catch(rollback){events.rollbackError=rollback.message;}
  }
  fs.writeFileSync(backup+'/deployment-failed.json',json(events)+'\n');throw Error(json(events));
 }
})().catch(e=>{console.error(e.message);process.exitCode=1});
