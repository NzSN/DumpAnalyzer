const fs=require('node:fs'),cp=require('node:child_process');
const control=require('./p6-ledger-control.cjs');
const runtime='D:/Services/dump-ledger-runtime',app='D:/Services/dump-ledger';
const record=process.argv[2];
if(!/^D:\/Services\/dump-ledger-runtime\/backups\/p6-production-20261020-verified\/launch-[a-z0-9-]+\.json$/.test(record||''))throw Error('Unexpected launch record path');
const fd=fs.openSync(record,'wx',0o600);
let child,exited,owned;
(async()=>{
 try{
  const log=fs.openSync(runtime+'/logs/backend.log','a');
  child=cp.spawn('D:/Services/node24/node.exe',[app+'/dist/src/main.js'],{cwd:app,env:process.env,stdio:['ignore',log,log],detached:true,windowsHide:true});
  exited=new Promise(resolve=>child.once('exit',resolve));
  fs.closeSync(log);
  await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject)});
  owned=control.identity(child.pid);
  if(!owned||!owned.isBackend)throw Error('Launched backend identity unavailable');
  fs.writeFileSync(fd,JSON.stringify({startedUtc:new Date().toISOString(),nativeIdentity:owned})+'\n');fs.closeSync(fd);
  fs.writeFileSync(runtime+'/backend.pid',String(child.pid)+'\n');
  child.unref();
 }catch(e){
  let childExitConfirmed=!child?.pid;
  if(child?.pid){
   try{
    child.kill();
    await Promise.race([exited,new Promise((_,reject)=>setTimeout(()=>reject(Error('Child exit timeout')),10000))]);
    childExitConfirmed=true;
   }catch{}
  }
  try{fs.writeFileSync(record,JSON.stringify({status:'failed',nativeIdentity:owned||null,childPid:child?.pid||null,childExitConfirmed})+'\n')}catch{}
  child?.unref();
  try{fs.closeSync(fd)}catch{}
  throw e;
 }
})().catch(e=>{console.error(e.message);process.exitCode=1});
