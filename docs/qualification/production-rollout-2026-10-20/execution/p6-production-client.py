from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,sqlite3,ssl,subprocess,sys,urllib.request,urllib.error

statepath=Path('/tmp/dumpanalyzer-p6-production-current.json'); state=json.loads(statepath.read_text())
base=Path(state['base']); backup=Path(state['localBackup']); os.umask(0o077)
pid=int(subprocess.check_output(['systemctl','--user','show','dump-analyzer.service','-p','MainPID','--value'],text=True).strip())
env=dict(x.split('=',1) for x in Path(f'/proc/{pid}/environ').read_text().split('\0') if '=' in x)
assert env['DUMP_ANALYZER_BASE_URL']=='https://192.168.150.219:4080'
assert env['DUMP_ANALYZER_WRITE_BACK']=='off' and env['DUMP_ANALYZER_SCHEDULER']=='off'
token=env.get('DUMP_ANALYZER_TOKEN')
if not token:
 db=sqlite3.connect('file:'+env['DUMP_ANALYZER_STATE_DIR']+'/analyzer.sqlite?mode=ro',uri=True)
 token=db.execute("SELECT value FROM secrets WHERE name='analyzer_token'").fetchone()[0];db.close()
assert token
context=ssl.create_default_context(cafile=env['DUMP_ANALYZER_TLS_CA_CERT'])
def get(path,auth=True):
 headers={'Authorization':'Bearer '+token} if auth else {}
 req=urllib.request.Request(env['DUMP_ANALYZER_BASE_URL']+path,headers=headers)
 try:
  with urllib.request.urlopen(req,context=context,timeout=20) as r:return r.status,r.read()
 except urllib.error.HTTPError as e:return e.code,e.read()
mode=sys.argv[1]
if mode=='probe-deployed':
 status,body=get('/api/v2/capabilities');caps=json.loads(body)
 assert status==200 and caps['richReports']=={'schemaVersion':2,'maxReportBytes':524288,'maxRequestBytes':1048576}
 auth,_=get('/api/v2/capabilities',auth=False);assert auth==401
 code,listing=get('/api/v1/dumps/'+state['canaryDumpId']+'/analyses');assert code==200
 assert json.loads(listing)==json.loads((backup/'remote-canary-list-before.json').read_bytes())
 result={'utc':datetime.now(timezone.utc).isoformat(),'capabilitiesStatus':status,'capabilities':caps,'unauthenticatedCapabilitiesStatus':auth,'existingCanaryAnalysesUnchanged':True,'writesPerformed':0}
 (backup/'http-deployed.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
elif mode=='before':
 status,body=get('/api/v2/capabilities')
 assert status==404
 code,listing=get('/api/v1/dumps/'+state['canaryDumpId']+'/analyses')
 assert code==200
 (backup/'remote-canary-list-before.json').write_bytes(listing)
 result={'utc':datetime.now(timezone.utc).isoformat(),'capabilitiesStatus':status,'canaryListStatus':code,'canaryExistingReports':len(json.loads(listing)['analyses'])}
 (backup/'http-before.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
elif mode=='publish':
 status,body=get('/api/v2/capabilities'); capabilities=json.loads(body)
 assert status==200 and capabilities['richReports']=={'schemaVersion':2,'maxReportBytes':524288,'maxRequestBytes':1048576}
 childenv=os.environ.copy();childenv.update(env);childenv['DUMP_ANALYZER_TOKEN']=token
 command=[str(Path(state['analyzerRoot'])/'target/release/examples/report-delivery-canary'),str(backup/'canary-report.json'),str(backup/'selected-delivery.sqlite')]
 assert not (backup/'selected-delivery.sqlite').exists()
 with (backup/'publication.log').open('w') as out:
  run=subprocess.run(command,cwd=state['analyzerRoot'],env=childenv,stdout=out,stderr=subprocess.STDOUT,timeout=120)
 if run.returncode:raise RuntimeError('Selected publisher failed; private log retained')
 result=json.loads((backup/'publication.log').read_text().strip().splitlines()[-1])
 assert result['digest']==state['canaryDigest'] and result['reportId']==state['canaryReportId']
 result.update({'utc':datetime.now(timezone.utc).isoformat(),'capabilities':capabilities,'exitCode':run.returncode,'publisherBinarySha256':hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(),'singleSelectedReport':True})
 state['canaryAnalysisId']=result['analysisId'];statepath.write_text(json.dumps(state,indent=2)+'\n')
 (backup/'publication.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
elif mode in ['verify','verify-after-restart']:
 path='/api/v2/dumps/'+state['canaryDumpId']+'/analyses/'+state['canaryAnalysisId']
 status,body=get(path);assert status==200
 detail=json.loads(body);canonical=detail['reportJson'].encode()
 assert canonical==(backup/'canary-report.json').read_bytes()
 assert detail['reportDigest']==state['canaryDigest']==hashlib.sha256(canonical).hexdigest()
 unauthorized,_=get(path,auth=False);assert unauthorized==401
 code,raw=get('/api/v1/dumps/'+state['canaryDumpId']+'/analyses');assert code==200
 listing=json.loads(raw)['analyses']; before=json.loads((backup/'remote-canary-list-before.json').read_bytes())['analyses']
 assert len(listing)==len(before)+1
 assert all(item in listing for item in before)
 assert all('reportJson' not in item and 'reportDigest' not in item for item in listing)
 assert len([item for item in listing if item['analysisId']==state['canaryAnalysisId']])==1
 (backup/(mode+'-remote.json')).write_bytes(body)
 result={'utc':datetime.now(timezone.utc).isoformat(),'analysisId':state['canaryAnalysisId'],'reportId':state['canaryReportId'],'digest':state['canaryDigest'],'canonicalBytes':len(canonical),'identicalRemoteDetail':True,'authenticatedStatus':status,'unauthenticatedStatus':unauthorized,'compactOnlyV1List':True,'previousAnalysesPreserved':True,'oneAddedAnalysis':True,'afterCompanionRestart':mode=='verify-after-restart'}
 (backup/(mode+'.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
else:raise RuntimeError('Unknown operation')
