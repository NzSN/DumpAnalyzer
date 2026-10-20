const cp=require('node:child_process'),control=require('./p6-ledger-control.cjs');
(async()=>{
 const child=cp.spawn(process.execPath,['-e','setTimeout(()=>{},60000)'],{stdio:'ignore',windowsHide:true});
 let owned;
 try{
  await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject)});
  owned=control.identity(child.pid);if(!owned)throw Error('No child identity');
  let refused=false;try{await control.stop({...owned,createdUtc:'deliberately-wrong'})}catch{refused=true}
  if(!refused||!control.same(control.identity(child.pid),owned))throw Error('Identity guard failed');
  const stopped=await control.stop(owned);
  if(!stopped.exitConfirmed||control.identity(child.pid)!==null)throw Error('Non-listening child survived');
  console.log(JSON.stringify({passed:true,nativePid:child.pid,creationIdentityCaptured:true,wrongIdentityRefused:true,nonListeningChildExitConfirmed:true}));
 }finally{if(owned&&control.same(control.identity(child.pid),owned))await control.stop(owned);else if(!owned)child.kill();}
})().catch(e=>{console.error(e.message);process.exitCode=1});
