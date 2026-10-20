const cp=require('node:child_process'),crypto=require('node:crypto');
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
function identity(pid){
 if(!Number.isSafeInteger(pid)||pid<1)throw Error('Invalid native process ID');
 const script=`$p=Get-CimInstance Win32_Process -Filter "ProcessId = ${pid}";if($null -ne $p){@{pid=[int]$p.ProcessId;createdUtc=$p.CreationDate.ToUniversalTime().ToString('o');executable=$p.ExecutablePath;command=$p.CommandLine}|ConvertTo-Json -Compress}`;
 const raw=cp.execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8'}).trim();
 if(!raw)return null;
 const p=JSON.parse(raw);
 return {pid:p.pid,createdUtc:p.createdUtc,executable:p.executable,commandSha256:hash(p.command||''),isBackend:(p.command||'').replaceAll('\\','/').toLowerCase().includes('d:/services/dump-ledger/dist/src/main.js')};
}
const same=(a,b)=>a&&b&&a.pid===b.pid&&a.createdUtc===b.createdUtc&&a.executable===b.executable&&a.commandSha256===b.commandSha256;
async function stop(expected){
 const current=identity(expected.pid);
 if(!current)return {alreadyExited:true};
 if(!same(current,expected))throw Error('Native process identity changed; refusing to terminate');
 cp.execFileSync('taskkill',['/PID',String(expected.pid),'/F'],{encoding:'utf8'});
 for(let i=0;i<20;i++){
  const p=identity(expected.pid);if(!p||!same(p,expected))return {terminated:true,exitConfirmed:true};
  await new Promise(r=>setTimeout(r,250));
 }
 throw Error('Owned native process did not exit');
}
module.exports={identity,same,stop};
