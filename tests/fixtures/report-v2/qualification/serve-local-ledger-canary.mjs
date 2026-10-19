// Qualification-only service. Always a fresh or explicitly resumed /tmp store;
// no production database, credentials, network source, or deployment process.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const ledgerCheckout=resolve(process.env.DUMP_LEDGER_CHECKOUT || '/home/nzsn/Repos/dump-ledger');
const fixture=resolve(process.argv[2] || '/tmp/rich-report-canary-20261015/null-read.dmp');
const stateDir=resolve(process.argv[3] || mkdtempSync('/tmp/dump-ledger-rich-canary-'));
assert(stateDir.startsWith('/tmp/dump-ledger-rich-canary-'), 'canary state must stay under /tmp/dump-ledger-rich-canary-*');
mkdirSync(stateDir,{recursive:true,mode:0o700});
assert.equal(realpathSync(stateDir),stateDir,'canary state must not be a symlink');
const port=Number(process.argv[4] || 0);
assert(Number.isInteger(port) && port >= 0 && port <= 65535);
const dummyToken='rich-report-canary-token-not-for-production-20261015';
const dummyPassword='rich-report-canary-password-not-for-production-20261015';
const expectedSha='31994b27ca9885d54dae6a6f6c0a7fa56c0a4c99e2523a71fb15ed57969a146b';
const dumpId='dump_00000000000000000000000001';
const load=rel=>import(pathToFileURL(join(ledgerCheckout,'dist/src',rel)).href);
const [{createDumpLedgerEngine,RandomIds}, {FilesystemVault}, {createVaultMinidumpInspectionPort}, {EngineHttpApplication}, {buildHttpServer}, {OperatorSessions,hashOperatorPassword}, {EngineUploadLifecycle,EngineUploadPostProcessor,VaultUploadSink}]=await Promise.all([
  load('engine/dump-ledger-engine.js').then(async m=>({...m,RandomIds:(await load('engine/dependencies.js')).RandomIds})),
  load('vault/filesystem-vault.js'),load('inspection/index.js'),load('http/application.js'),load('http/server.js'),load('auth/sessions.js'),load('intake/intake-facade.js')
]);
const vault=new FilesystemVault(join(stateDir,'vault'));
const randomIds=new RandomIds();
const engine=createDumpLedgerEngine({databasePath:join(stateDir,'ledger.sqlite'),vault,inspection:createVaultMinidumpInspectionPort(vault),grantSecretKey:Buffer.alloc(32,0x71),ids:{next:kind=>kind==='dump'?dumpId:randomIds.next(kind)}});
const must=receipt=>{assert(receipt.ok,JSON.stringify(receipt,(_k,v)=>typeof v==='bigint'?v.toString():v));return receipt;};
if(!engine.snapshot().dumps.some(d=>d.dumpId===dumpId)){
  const bytes=readFileSync(fixture),actualSha=createHash('sha256').update(bytes).digest('hex');assert.equal(actualSha,expectedSha,'wrong controlled fixture dump');
  const customer=must(engine.execute({type:'CreateCustomer',displayName:'Rich report controlled qualification'}));
  const supportCase=must(engine.execute({type:'CreateCase',customerId:customer.customerId,title:'Controlled native null read fixture'}));
  const grant=must(engine.execute({type:'IssueGrant',caseId:supportCase.caseId,expiresAt:'2035-01-01T00:00:00.000Z',maxBytes:BigInt(bytes.length+1024)}));
  const begun=must(engine.execute({type:'BeginUpload',grantSecret:grant.grantSecret,originalName:'controlled-null-read.dmp'}));assert.equal(begun.dumpId,dumpId);
  vault.append(dumpId,bytes);vault.syncAndClose(dumpId);
  must(engine.execute({type:'SealUpload',dumpId,byteSize:BigInt(bytes.length),sha256:actualSha}));
  must(engine.execute({type:'PromoteObject',dumpId}));must(engine.execute({type:'MarkQuarantined',dumpId}));must(engine.execute({type:'AcceptDump',dumpId}));
}
const sealed=engine.snapshot().dumps.find(d=>d.dumpId===dumpId);assert.equal(sealed.phase,'available');assert.equal(sealed.sha256,expectedSha);
const sessions=new OperatorSessions({passwordHash:await hashOperatorPassword(dummyPassword),secureCookies:false});
const server=buildHttpServer({application:new EngineHttpApplication(engine,vault),sessions,analyzerTokenHash:createHash('sha256').update(dummyToken).digest(),uploadLifecycle:new EngineUploadLifecycle(engine),uploadSink:new VaultUploadSink(vault),uploadPostProcessor:new EngineUploadPostProcessor(engine),secureDeployment:false});
const address=await server.listen({host:'127.0.0.1',port});
const metadata={purpose:'isolated rich-report cross-binary qualification only',startedAt:new Date().toISOString(),pid:process.pid,url:address,stateDir,database:join(stateDir,'ledger.sqlite'),vault:join(stateDir,'vault'),fixture,dumpId,inputSha256:expectedSha,byteSize:sealed.byteSize.toString(),dummyToken,analysesAtStart:engine.listAnalyses(dumpId).map(a=>({analysisId:a.analysisId,reportDigest:a.facts?.reportDigest,reportId:a.facts?.reportId})),sourceCheckout:ledgerCheckout};
writeFileSync(join(stateDir,'service.json'),JSON.stringify(metadata,null,2)+'\n',{mode:0o600});
console.log(JSON.stringify(metadata));
let closing=false;
const shutdown=async signal=>{if(closing)return;closing=true;console.log(JSON.stringify({signal,analysesAtShutdown:engine.listAnalyses(dumpId).map(a=>({analysisId:a.analysisId,reportDigest:a.facts?.reportDigest}))}));await server.close();engine.close();};
process.once('SIGTERM',()=>shutdown('SIGTERM').then(()=>process.exit(0),error=>{console.error(error);process.exit(1);}));
process.once('SIGINT',()=>shutdown('SIGINT').then(()=>process.exit(0),error=>{console.error(error);process.exit(1);}));
