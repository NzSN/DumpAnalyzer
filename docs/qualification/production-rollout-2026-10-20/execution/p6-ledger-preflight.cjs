const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const cp=require('node:child_process');
const {createRequire}=require('node:module');
const app='D:/Services/dump-ledger';
const runtime='D:/Services/dump-ledger-runtime';
const tag='p6-production-20261020-verified';
const backup=path.join(runtime,'backups',tag);
const requireApp=createRequire(path.join(app,'package.json'));
const Database=requireApp('better-sqlite3');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const json=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x);
const snapshot=db=>Object.fromEntries(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(({name})=>{
 const rows=db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all();
 return [name,{rows:rows.length,sha256:hash(json(rows))}];
}));
(async()=>{
 const head=cp.execFileSync('git',['rev-parse','HEAD'],{cwd:app,encoding:'utf8'}).trim();
 if(head!=='69eb3d3ad177421f8b28697ca5e9a95254c68530')throw Error('Unexpected deployed HEAD');
 const dirty=cp.execFileSync('git',['status','--porcelain'],{cwd:app,encoding:'utf8'}).trim();
 if(dirty && dirty!=='?? .msf-diag.mjs')throw Error('Unreviewed production source changes');
 const dbpath=path.join(runtime,'data/ledger.sqlite');
 const db=new Database(dbpath,{readonly:true,fileMustExist:true});
 db.defaultSafeIntegers(true);
 const integrity=db.pragma('integrity_check');
 if(json(integrity)!=='[{"integrity_check":"ok"}]')throw Error('SQLite integrity failed');
 const tables=snapshot(db);
 const migrations=db.prepare('SELECT version FROM schema_migrations ORDER BY version').all().map(x=>Number(x.version));
 if(json(migrations)!==json([1,2,3,4,5,6,7,8,10]))throw Error('Unexpected migration baseline');
 const dump=db.prepare('SELECT dump_id,phase,sha256 FROM dumps WHERE dump_id=?').get('dump_4142A5B57E5A4C01A1C47C883E');
 if(!dump || dump.phase!=='available' || dump.sha256!=='dd0b98caf4a9a0e8770717ed46cf94b1922a7043797f48878f824dad7b203aac')throw Error('Canary dump not available with matching sealed SHA');
 const analyses=db.prepare('SELECT analyzer_name,analyzer_version,kind,input_sha256 FROM dump_analyses WHERE dump_id=?').all(dump.dump_id);
 if(analyses.some(a=>a.analyzer_name==='dump-analyzer'&&a.analyzer_version==='0.2.0'&&a.kind==='triage'&&a.input_sha256===dump.sha256))throw Error('Canary identity already published; inspect binding before using');
 if(analyses.length>=64)throw Error('Canary report limit reached');
 if(fs.existsSync(backup))throw Error('Backup destination already exists');
 fs.mkdirSync(backup,{recursive:true,mode:0o700});
 await db.backup(path.join(backup,'online-before.sqlite'));
 const saved=new Database(path.join(backup,'online-before.sqlite'),{readonly:true}); saved.defaultSafeIntegers(true);
 if(json(snapshot(saved))!==json(tables))throw Error('Online backup table snapshot differed; stop and review concurrent writes');
 saved.close();
 for(const name of ['.env','start.sh','proxy.mjs','proxy-cert.pem','proxy-key.pem','proxy-server-cert.pem','proxy-server-key.pem']){
  const source=path.join(runtime,name);
  if(fs.existsSync(source)){fs.copyFileSync(source,path.join(backup,name));fs.chmodSync(path.join(backup,name),0o600);}
 }
 for(const name of ['dist','packages/http-contracts/dist']){
  const src=path.join(app,name);
  if(!fs.existsSync(src))throw Error('Missing deployed build '+name);
  fs.cpSync(src,path.join(backup,'build-before',name),{recursive:true});
 }
 const info={schema:'dumpanalyzer.p6.production-preflight/v1',utc:new Date().toISOString(),head,node:process.version,backup,database:dbpath,integrity:'ok',migrations,tables,canary:dump,canaryExistingAnalyses:analyses.length,phases:db.prepare('SELECT phase,COUNT(*) AS count FROM dumps GROUP BY phase ORDER BY phase').all(),unchangedConfigurationSha256:hash(fs.readFileSync(path.join(runtime,'.env'))),startScriptSha256:hash(fs.readFileSync(path.join(runtime,'start.sh'))),untrackedPreserved:dirty,publicHealth:(await fetch('http://127.0.0.1:4081/health')).status};
 fs.writeFileSync(path.join(backup,'preflight.json'),json(info)+'\n');
 db.close();
 console.log(json(info));
})().catch(e=>{console.error(e.message);process.exitCode=1});
