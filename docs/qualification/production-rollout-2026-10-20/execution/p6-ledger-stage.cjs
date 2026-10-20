const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const {pathToFileURL}=require('node:url'); const {createRequire}=require('node:module');
const app='D:/Services/dump-ledger',runtime='D:/Services/dump-ledger-runtime';
const backup=runtime+'/backups/p6-production-20261020-verified';
const release=runtime+'/releases/p6-7c2a51b-20261020';
const artifact=runtime+'/tmp/p6-deploy-build-20261020.tar.gz';
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const json=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x);
const snapshot=db=>Object.fromEntries(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(({name})=>{const rows=db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all();return[name,{rows:rows.length,sha256:hash(json(rows))}]}));
(async()=>{
 if(hash(fs.readFileSync(artifact))!=='044fb2f374f533e8488730dd3df309553b82637e5d3bbdd67ed0a0e6f1e7bad1')throw Error('Build archive hash mismatch');
 fs.mkdirSync(path.dirname(release),{recursive:true});
 if(fs.existsSync(release)){if(fs.readdirSync(release).length)throw Error('Release destination is not empty');}else fs.mkdirSync(release);
 cp.execFileSync('tar',['--force-local','-xzf',artifact,'-C',release]);
 const manifest=JSON.parse(fs.readFileSync(release+'/build-manifest.json','utf8'));
 if(manifest.sourceCommit!=='7c2a51b51d2638c462778c17fe9421632297b236'||!manifest.sourceUnchanged)throw Error('Unqualified build');
 for(const [name,item]of Object.entries(manifest.files)){
  if(!name.startsWith('dist/')&&!name.startsWith('packages/http-contracts/dist/'))throw Error('Unexpected build path');
  const data=fs.readFileSync(path.join(release,name));if(data.length!==item.bytes||hash(data)!==item.sha256)throw Error('Build mismatch '+name);
 }
 const Database=createRequire(app+'/package.json')('better-sqlite3');
 const dbpath=backup+'/migration-dry-run.sqlite';fs.copyFileSync(backup+'/online-before.sqlite',dbpath,fs.constants.COPYFILE_EXCL);
 const db=new Database(dbpath);db.defaultSafeIntegers(true);
 const before=snapshot(db);
 const {applyMigrations}=await import(pathToFileURL(release+'/dist/src/ledger/migrations.js').href);
 applyMigrations(db);
 const after=snapshot(db);
 for(const[name,value]of Object.entries(before))if(name!=='schema_migrations'&&json(after[name])!==json(value))throw Error('Migration changed old table '+name);
 const versions=db.prepare('SELECT version FROM schema_migrations ORDER BY version').all().map(x=>Number(x.version));
 if(json(versions)!==json([1,2,3,4,5,6,7,8,9,10]))throw Error('Migration version mismatch');
 if(after.analysis_details?.rows!==0)throw Error('Unexpected rich detail state');
 if(json(db.pragma('integrity_check'))!=='[{"integrity_check":"ok"}]'||db.pragma('foreign_key_check').length)throw Error('Migrated integrity failed');
 db.close();
 const result={schema:'dumpanalyzer.p6.production-migration/v1',utc:new Date().toISOString(),release,sourceCommit:manifest.sourceCommit,artifactSha256:hash(fs.readFileSync(artifact)),verifiedBuildFiles:Object.keys(manifest.files).length,migrations:versions,preservedOldTables:Object.keys(before).filter(n=>n!=='schema_migrations'),integrity:'ok',foreignKeyViolations:0,analysisDetails:0,tests:manifest.tests};
 fs.writeFileSync(backup+'/migration-proof.json',json(result)+'\n');
 console.log(json(result));
})().catch(e=>{console.error(e.message);process.exitCode=1});
