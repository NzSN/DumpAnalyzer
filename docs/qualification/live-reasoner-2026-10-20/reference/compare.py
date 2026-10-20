#!/usr/bin/env python3
"""Read-only comparison of a synthetic live capture against the offline baseline."""
import json, pathlib, sys
base=pathlib.Path(__file__).resolve().parent
baseline=json.loads((base/'baseline.json').read_text())['capture']
live=json.loads(pathlib.Path(sys.argv[1]).read_text())['capture']
checks={}
for key in ['exception','context','stack','symbols','completeness']:
    checks[key]=live[key]==baseline[key]
checks['mechanism']=live['rootCause']['mechanism']==baseline['rootCause']['mechanism']
checks['originalEvidencePreserved']=[e for e in live['evidence'] if e['id']!='assessment-model']==baseline['evidence']
for key in ['debuggerVersion','architecture','pointerWidth','processId']:
    checks['provenance.'+key]=live['provenance'][key]==baseline['provenance'][key]
checks['provider']=live['provenance']['provider']=='claude-cdb'
checks['observedModel']=bool(live['provenance']['model'])
checks['analysisRevision']=live['provenance']['analysisRevision']==baseline['provenance']['analysisRevision']+';reasoner=claude-host-v2.1'
model=[e for e in live['evidence'] if e['id']=='assessment-model']
checks['singlePresentModelAssessment']=len(model)==1 and model[0]['status']=='present' and not model[0]['truncated']
checks['modelEvidenceEqualsAcceptedCause']=len(model)==1 and json.loads(model[0]['text'])==live['rootCause']
cause=live['rootCause']
checks['unconfirmedOrigin']=cause['status'] in ['hypothesis','unknown'] and cause['ruleId'] is None
ids={e['id'] for e in baseline['evidence']}
refs=list(cause['evidenceRefs'])+list(cause['mechanism']['evidenceRefs'])
for h in cause['hypotheses']:
    refs+=h['evidenceRefs']
checks['actualEvidenceRefs']=all(ref in ids for ref in refs)
checks['everyHypothesisQualified']=all(h['evidenceRefs'] and h['missingEvidence'] and h['nextChecks'] for h in cause['hypotheses'])
checks['causeNextChecks']=bool(cause['nextChecks'])
checks['causeMissingEvidence']=bool(cause['missingEvidence'])
result={'allPassed':all(checks.values()),'checks':checks,'scope':'Synthetic receipt preservation comparison; no live tool-denial observation implied','outcomeComparison':'Not available: existing live-test receipt omits outcome'}
print(json.dumps(result,indent=2))
sys.exit(0 if result['allPassed'] else 1)
