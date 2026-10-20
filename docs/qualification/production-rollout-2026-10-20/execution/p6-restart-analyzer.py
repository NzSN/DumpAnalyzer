from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,sqlite3,subprocess,time,urllib.request

state=json.loads(Path('/tmp/dumpanalyzer-p6-production-current.json').read_text());root=Path(state['analyzerRoot']);backup=Path(state['localBackup']);os.umask(0o077)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
unit=['systemctl','--user'];binary=root/'target/release/dump-analyzer'
before=json.loads((backup/'before.json').read_text())
assert not subprocess.check_output(['git','diff','--name-only','--','src','Cargo.toml','Cargo.lock','examples'],cwd=root,text=True).strip()
assert sha(Path('/home/nzsn/.config/dump-analyzer/env'))==before['environmentFileSha256']
dbpath=backup.parent.parent/'analyzer.sqlite'; expected=sha(binary)
subprocess.run(unit+['stop','dump-analyzer.service'],check=True)
stopped=sqlite3.connect('file:'+str(dbpath)+'?mode=ro',uri=True);out=sqlite3.connect(backup/'stopped-before.sqlite');stopped.backup(out);out.close()
def fingerprint(db,name):
 rows=db.execute('SELECT * FROM "'+name+'" ORDER BY rowid').fetchall()
 return {'rows':len(rows),'sha256':hashlib.sha256(json.dumps(rows,ensure_ascii=True,separators=(',',':'),default=lambda b:{'bytes':bytes(b).hex()}).encode()).hexdigest()}
preserved=['local_reports','report_details','secrets','settled_jobs','byte_cache']
for name in preserved:assert fingerprint(stopped,name)==before['tables'][name],name
assert stopped.execute('PRAGMA integrity_check').fetchall()==[('ok',)];stopped.close()
result={'utc':datetime.now(timezone.utc).isoformat(),'beforePid':before['pid'],'beforeBinarySha256':before['binarySha256'],'binarySha256':expected,'stoppedBackup':str(backup/'stopped-before.sqlite')}
try:
 subprocess.run(unit+['start','dump-analyzer.service'],check=True)
 for _ in range(60):
  try:
   pid=int(subprocess.check_output(unit+['show','dump-analyzer.service','-p','MainPID','--value'],text=True).strip())
   with urllib.request.urlopen('http://127.0.0.1:4180/api/status',timeout=2) as r: status=json.load(r)
   assert pid>0 and sha(Path(f'/proc/{pid}/exe'))==expected
   break
  except Exception:time.sleep(.5)
 else:raise RuntimeError('Analyzer did not become healthy')
 env=dict(x.split('=',1) for x in Path(f'/proc/{pid}/environ').read_text().split('\0') if '=' in x)
 assert env['DUMP_ANALYZER_SCHEDULER']=='off' and env['DUMP_ANALYZER_WRITE_BACK']=='off' and env['DUMP_ANALYZER_RUNNER']=='cdb-ssh'
 db=sqlite3.connect('file:'+str(dbpath)+'?mode=ro',uri=True)
 for name in preserved:assert fingerprint(db,name)==before['tables'][name],name
 assert db.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
 result.update({'status':'deployed','pid':pid,'httpStatus':200,'version':status.get('version'),'preservedTables':preserved,'reportCount':db.execute('SELECT COUNT(*) FROM local_reports').fetchone()[0],'richReportCount':db.execute('SELECT COUNT(*) FROM report_details').fetchone()[0],'scheduler':'off','writeBack':'off','runner':'cdb-ssh','integrity':'ok','configurationUnchanged':True})
 db.close();(backup/'analyzer-deployment.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
except Exception as e:
 subprocess.run(unit+['stop','dump-analyzer.service'],check=True)
 restored=binary.with_name('dump-analyzer.rollback');restored.write_bytes((backup/'dump-analyzer.before').read_bytes());restored.chmod(0o755);os.replace(restored,binary)
 subprocess.run(unit+['start','dump-analyzer.service'],check=True)
 result.update({'status':'rolled-back','reason':str(e),'databaseRestored':False})
 (backup/'analyzer-deployment-failed.json').write_text(json.dumps(result,indent=2)+'\n');raise
