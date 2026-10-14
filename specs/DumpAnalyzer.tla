------------------------------ MODULE DumpAnalyzer ------------------------------
EXTENDS FiniteSets, Naturals, Sequences

\* DumpAnalyzer job-loop model (docs/analyzer-design.md).
\*
\* The model covers the analyzer-side safety story: a dump discovered through
\* the DumpLedger catalog becomes one analysis job; the agent fetches,
\* verifies, and analyzes the pinned bytes; the verdict-writer submits an
\* idempotent report; purges, transient runner failures, and analyzer crashes
\* may interleave at any point. Exactly-once visible effect comes from the
\* server identity (dump, content) plus idempotent replay, never from
\* suppressing re-runs.
\*
\* Finite model slots. Production identifiers are opaque strings; the
\* client-local adapter maps these integer slots to branded identifiers.
Dumps    == 1..2
Contents == 1..2

NoContent == 0

\* Dump bytes are immutable once available, so each dump has exactly one
\* content slot; content c models the sealed sha256 of dump c.
\* @type: Seq(Int);
DumpContent == <<1, 2>>

\* One analysis kind ("triage") at one pinned analyzer version is modeled, so
\* report identity reduces to (dump, content). Additional kinds or versions
\* multiply the identity tuple without changing the protocol.
MaxEvents   == 4   \* abstract intake events visible on the feed
MaxAttempts == 2   \* transient failure budget per job

JobStates == {"none", "discovered", "claimed", "fetching", "staged",
              "analyzing", "reporting", "done", "dropped", "failed"}

ServerDumpStates == {"available", "purged"}

VARIABLES
  \* @type: Seq(Str);
  serverDump,      \* dump slot -> ServerDumpStates (server truth)
  \* @type: Set(<<Int, Int>>);
  serverReports,   \* accepted report identities: (dump, content)
  \* @type: Seq(Str);
  jobState,        \* dump slot -> JobStates; at most one job per dump
  \* @type: Seq(Int);
  jobContent,      \* dump slot -> content pinned at fetch, or NoContent
  \* @type: Seq(Bool);
  bytesVerified,   \* dump slot -> staged bytes passed sha256 verification
  \* @type: Seq(Int);
  attempts,        \* dump slot -> transient failures so far
  \* @type: Int;
  eventsSeen,      \* abstract intake events visible on the feed so far
  \* @type: Int;
  eventCursor,     \* persisted feed cursor; never decreases
  \* @type: Int;
  lastEventCursor, \* ghost: cursor value before the last move (monotonicity)
  \* @type: Bool;
  agentUp,         \* FALSE after Crash until Recover
  \* @type: Str;
  action_taken,    \* last non-stuttering transition, for traces
  \* @type: { dump: Int, content: Int, kind: Str };
  parameters       \* complete inputs of the last transition

vars == <<serverDump, serverReports, jobState, jobContent, bytesVerified,
          attempts, eventsSeen, eventCursor, lastEventCursor, agentUp,
          action_taken, parameters>>

Act(name, d, c) ==
  /\ action_taken' = name
  /\ parameters' = [dump |-> d, content |-> c, kind |-> "triage"]

Init ==
  /\ serverDump = <<"available", "available">>
  /\ serverReports = {}
  /\ jobState = <<"none", "none">>
  /\ jobContent = <<NoContent, NoContent>>
  /\ bytesVerified = <<FALSE, FALSE>>
  /\ attempts = <<0, 0>>
  /\ eventsSeen = 0
  /\ eventCursor = 0
  /\ lastEventCursor = 0
  /\ agentUp = TRUE
  /\ action_taken = "init"
  /\ parameters = [dump |-> 0, content |-> NoContent, kind |-> ""]

\* --- Server-side environment ---------------------------------------------

\* Intake on the DumpLedger side, abstracted to an event becoming visible on
\* the feed. Accrues whether or not the analyzer is up.
IntakeEvent ==
  /\ eventsSeen < MaxEvents
  /\ eventsSeen' = eventsSeen + 1
  /\ Act("intake", 0, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, jobState, jobContent,
                 bytesVerified, attempts, eventCursor, lastEventCursor,
                 agentUp>>

\* Retention purges a dump on the server: accepted reports cascade-delete
\* with it, and a purge event becomes visible on the feed. The analyzer's
\* local job is NOT eagerly modified — it learns of the purge either through
\* the event feed (PurgeObserved) or at its next server contact
\* (FetchPurged, SubmitPurged). A settled (done) job keeps its local
\* terminal record; the report is gone from the server.
Purge(d) ==
  /\ serverDump[d] = "available"
  /\ eventsSeen < MaxEvents
  /\ serverDump' = [serverDump EXCEPT ![d] = "purged"]
  /\ serverReports' = serverReports \ {r \in serverReports : r[1] = d}
  /\ eventsSeen' = eventsSeen + 1
  /\ Act("purge", d, NoContent)
  /\ UNCHANGED <<jobState, jobContent, bytesVerified, attempts, eventCursor,
                 lastEventCursor, agentUp>>

\* The feed follower applies a purge event (sync.rs drop_job): active jobs
\* that have not reached a server-contact stage are dropped eagerly.
\* Fetching/reporting jobs instead observe the purge at their server call
\* (FetchPurged/SubmitPurged).
PurgeObserved(d) ==
  /\ agentUp
  /\ serverDump[d] = "purged"
  /\ jobState[d] \in {"discovered", "claimed", "staged", "analyzing"}
  /\ jobState' = [jobState EXCEPT ![d] = "dropped"]
  /\ jobContent' = [jobContent EXCEPT ![d] = NoContent]
  /\ bytesVerified' = [bytesVerified EXCEPT ![d] = FALSE]
  /\ Act("purge-observed", d, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, attempts, eventsSeen,
                 eventCursor, lastEventCursor, agentUp>>

\* --- Discovery and claiming ----------------------------------------------

\* Catalog scan or feed observation discovers an available dump.
Discover(d) ==
  /\ agentUp
  /\ serverDump[d] = "available"
  /\ jobState[d] = "none"
  /\ jobState' = [jobState EXCEPT ![d] = "discovered"]
  /\ Act("discover", d, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, jobContent, bytesVerified,
                 attempts, eventsSeen, eventCursor, lastEventCursor, agentUp>>

Claim(d) ==
  /\ agentUp
  /\ jobState[d] = "discovered"
  /\ jobState' = [jobState EXCEPT ![d] = "claimed"]
  /\ Act("claim", d, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, jobContent, bytesVerified,
                 attempts, eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* --- Fetch and verify ----------------------------------------------------

BeginFetch(d) ==
  /\ agentUp
  /\ jobState[d] = "claimed"
  /\ jobState' = [jobState EXCEPT ![d] = "fetching"]
  /\ Act("begin-fetch", d, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, jobContent, bytesVerified,
                 attempts, eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* Bytes staged and the job pins the dump's sealed content. The pin is
\* durable local state: it survives Crash so a reporting job can re-submit.
Stage(d) ==
  /\ agentUp
  /\ jobState[d] = "fetching"
  /\ serverDump[d] = "available"
  /\ jobState' = [jobState EXCEPT ![d] = "staged"]
  /\ jobContent' = [jobContent EXCEPT ![d] = DumpContent[d]]
  /\ bytesVerified' = [bytesVerified EXCEPT ![d] = FALSE]
  /\ Act("stage", d, DumpContent[d])
  /\ UNCHANGED <<serverDump, serverReports, attempts, eventsSeen,
                 eventCursor, lastEventCursor, agentUp>>

\* A dump purged mid-fetch invalidates the job at its next server touch.
FetchPurged(d) ==
  /\ agentUp
  /\ jobState[d] = "fetching"
  /\ serverDump[d] = "purged"
  /\ jobState' = [jobState EXCEPT ![d] = "dropped"]
  /\ jobContent' = [jobContent EXCEPT ![d] = NoContent]
  /\ Act("fetch-purged", d, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, bytesVerified, attempts,
                 eventsSeen, eventCursor, lastEventCursor, agentUp>>

VerifyOk(d) ==
  /\ agentUp
  /\ jobState[d] = "staged"
  /\ jobState' = [jobState EXCEPT ![d] = "analyzing"]
  /\ bytesVerified' = [bytesVerified EXCEPT ![d] = TRUE]
  /\ Act("verify-ok", d, jobContent[d])
  /\ UNCHANGED <<serverDump, serverReports, jobContent, attempts,
                 eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* Local staging corruption: hash mismatch means refetch, bounded by the
\* transient budget.
VerifyCorrupt(d) ==
  /\ agentUp
  /\ jobState[d] = "staged"
  /\ attempts[d] < MaxAttempts
  /\ jobState' = [jobState EXCEPT ![d] = "fetching"]
  /\ bytesVerified' = [bytesVerified EXCEPT ![d] = FALSE]
  /\ attempts' = [attempts EXCEPT ![d] = @ + 1]
  /\ Act("verify-corrupt", d, jobContent[d])
  /\ UNCHANGED <<serverDump, serverReports, jobContent, eventsSeen,
                 eventCursor, lastEventCursor, agentUp>>

\* --- Analysis and write-back ---------------------------------------------

\* The toolchain produced a verdict (outcome completed or failed; both are
\* reports). Safety does not distinguish them.
AnalyzeCompletes(d) ==
  /\ agentUp
  /\ jobState[d] = "analyzing"
  /\ bytesVerified[d]
  /\ jobState' = [jobState EXCEPT ![d] = "reporting"]
  /\ Act("analyze-completes", d, jobContent[d])
  /\ UNCHANGED <<serverDump, serverReports, jobContent, bytesVerified,
                 attempts, eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* Infrastructure failure (transport down, CDB crashed, timeout): not a
\* verdict. Bounded retry re-enters at fetch; the workspace is wiped.
RunnerFailed(d) ==
  /\ agentUp
  /\ jobState[d] = "analyzing"
  /\ attempts[d] < MaxAttempts
  /\ jobState' = [jobState EXCEPT ![d] = "claimed"]
  /\ bytesVerified' = [bytesVerified EXCEPT ![d] = FALSE]
  /\ attempts' = [attempts EXCEPT ![d] = @ + 1]
  /\ Act("runner-failed", d, jobContent[d])
  /\ UNCHANGED <<serverDump, serverReports, jobContent, eventsSeen,
                 eventCursor, lastEventCursor, agentUp>>

\* Transient budget exhausted: terminal local failure, no report.
JobFailed(d) ==
  /\ agentUp
  /\ jobState[d] \in {"staged", "analyzing"}
  /\ attempts[d] = MaxAttempts
  /\ jobState' = [jobState EXCEPT ![d] = "failed"]
  /\ bytesVerified' = [bytesVerified EXCEPT ![d] = FALSE]
  /\ Act("job-failed", d, jobContent[d])
  /\ UNCHANGED <<serverDump, serverReports, jobContent, attempts,
                 eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* The server accepts and persists the report (201). The job stays in
\* reporting until the client observes the response; a crash between accept
\* and observation is the replay path (SubmitReplay after Recover).
SubmitAccept(d) ==
  /\ agentUp
  /\ jobState[d] = "reporting"
  /\ serverDump[d] = "available"
  /\ <<d, jobContent[d]>> \notin serverReports
  /\ serverReports' = serverReports \cup {<<d, jobContent[d]>>}
  /\ Act("submit-accept", d, jobContent[d])
  /\ UNCHANGED <<serverDump, jobState, jobContent, bytesVerified, attempts,
                 eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* The client observes the stored report and settles the job. This is both
\* the 201 happy path and the 200 idempotent replay after a crash: the
\* server's identity check makes them the same observation.
SubmitReplay(d) ==
  /\ agentUp
  /\ jobState[d] = "reporting"
  /\ <<d, jobContent[d]>> \in serverReports
  /\ jobState' = [jobState EXCEPT ![d] = "done"]
  /\ Act("submit-replay", d, jobContent[d])
  /\ UNCHANGED <<serverDump, serverReports, jobContent, bytesVerified,
                 attempts, eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* The dump was purged between analysis and submission: 404, drop.
SubmitPurged(d) ==
  /\ agentUp
  /\ jobState[d] = "reporting"
  /\ serverDump[d] = "purged"
  /\ jobState' = [jobState EXCEPT ![d] = "dropped"]
  /\ jobContent' = [jobContent EXCEPT ![d] = NoContent]
  /\ Act("submit-purged", d, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, bytesVerified, attempts,
                 eventsSeen, eventCursor, lastEventCursor, agentUp>>

\* --- Crash and recovery --------------------------------------------------

\* Volatile staging is lost on crash; durable job rows survive. The crash
\* itself only downs the agent; recovery then resets each mid-flight job back
\* to claimed for re-fetch and re-verification. Reporting jobs keep their
\* pinned content and re-submit idempotently.
Crash ==
  /\ agentUp
  /\ agentUp' = FALSE
  /\ Act("crash", 0, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, jobState, jobContent,
                 bytesVerified, attempts, eventsSeen, eventCursor,
                 lastEventCursor>>

CrashReset(d) ==
  /\ ~agentUp
  /\ jobState[d] \in {"fetching", "staged", "analyzing"}
  /\ jobState' = [jobState EXCEPT ![d] = "claimed"]
  /\ bytesVerified' = [bytesVerified EXCEPT ![d] = FALSE]
  /\ Act("crash-reset", d, jobContent[d])
  /\ UNCHANGED <<serverDump, serverReports, jobContent, attempts,
                 eventsSeen, eventCursor, lastEventCursor, agentUp>>

Recover ==
  /\ ~agentUp
  /\ \A d \in Dumps : jobState[d] \notin {"fetching", "staged", "analyzing"}
  /\ agentUp' = TRUE
  /\ Act("recover", 0, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, jobState, jobContent,
                 bytesVerified, attempts, eventsSeen, eventCursor,
                 lastEventCursor>>

\* --- Event feed ----------------------------------------------------------

\* The follower applies events up to the observed end and persists the new
\* cursor. The cursor never moves backward and never passes the observed end.
FollowFeed ==
  /\ agentUp
  /\ eventCursor < eventsSeen
  /\ lastEventCursor' = eventCursor
  /\ eventCursor' = eventsSeen
  /\ Act("follow", 0, NoContent)
  /\ UNCHANGED <<serverDump, serverReports, jobState, jobContent,
                 bytesVerified, attempts, eventsSeen, agentUp>>

Next ==
  \/ IntakeEvent
  \/ FollowFeed
  \/ Crash
  \/ Recover
  \/ \E d \in Dumps:
       \/ Purge(d)
       \/ PurgeObserved(d)
       \/ Discover(d)
       \/ Claim(d)
       \/ BeginFetch(d)
       \/ Stage(d)
       \/ FetchPurged(d)
       \/ VerifyOk(d)
       \/ VerifyCorrupt(d)
       \/ AnalyzeCompletes(d)
       \/ RunnerFailed(d)
       \/ JobFailed(d)
       \/ SubmitAccept(d)
       \/ SubmitReplay(d)
       \/ SubmitPurged(d)
       \/ CrashReset(d)

SafetySpec == Init /\ [][Next]_vars

\* --- Safety invariants ---------------------------------------------------

TypeOK ==
  /\ Len(serverDump) = Cardinality(Dumps)
  /\ \A d \in Dumps : serverDump[d] \in ServerDumpStates
  /\ serverReports \subseteq (Dumps \X Contents)
  /\ Len(jobState) = Cardinality(Dumps)
  /\ \A d \in Dumps : jobState[d] \in JobStates
  /\ Len(jobContent) = Cardinality(Dumps)
  /\ \A d \in Dumps : jobContent[d] \in Contents \cup {NoContent}
  /\ Len(bytesVerified) = Cardinality(Dumps)
  /\ \A d \in Dumps : bytesVerified[d] \in BOOLEAN
  /\ Len(attempts) = Cardinality(Dumps)
  /\ \A d \in Dumps : attempts[d] \in 0..MaxAttempts
  /\ eventsSeen \in 0..MaxEvents
  /\ eventCursor \in 0..MaxEvents
  /\ lastEventCursor \in 0..MaxEvents
  /\ agentUp \in BOOLEAN
  /\ action_taken \in {"init", "intake", "discover", "claim", "begin-fetch",
                       "stage", "fetch-purged", "verify-ok", "verify-corrupt",
                       "analyze-completes", "runner-failed", "job-failed",
                       "submit-accept", "submit-replay", "submit-purged",
                       "purge", "purge-observed", "crash", "crash-reset", "recover", "follow"}
  /\ parameters \in [dump : Dumps \cup {0},
                     content : Contents \cup {NoContent},
                     kind : {"triage", ""}]

\* Transient retries are bounded; terminal failure never reports.
AttemptsBounded ==
  \A d \in Dumps : attempts[d] <= MaxAttempts

\* The feed cursor never exceeds what was observed and never moved backward.
CursorBounded ==
  eventCursor <= eventsSeen

CursorMonotonic ==
  lastEventCursor <= eventCursor

\* A report on the server always pins the dump's true sealed content.
PinnedReport ==
  \A r \in serverReports : r[2] = DumpContent[r[1]]

\* Report identity is unique per dump (with one kind/version modeled, this is
\* the server-side idempotency guarantee).
UniqueReport ==
  \A d \in Dumps : Cardinality({r \in serverReports : r[1] = d}) <= 1

\* Purge cascades: no report survives its dump.
ReportRequiresAvailableDump ==
  \A r \in serverReports : serverDump[r[1]] = "available"

\* The toolchain never runs on unverified bytes.
AnalysisNeedsVerifiedBytes ==
  \A d \in Dumps : jobState[d] = "analyzing" => bytesVerified[d]

\* A job in write-back always carries its pinned content (durable across
\* crashes); a settled job analyzed exactly the pinned bytes.
ReportingPinsContent ==
  \A d \in Dumps :
    jobState[d] \in {"reporting", "done"} => jobContent[d] /= NoContent

\* A settled job is backed by a server report, unless its dump was later
\* purged (reports cascade with the dump; the local terminal record stays).
DoneConsistentWithReport ==
  \A d \in Dumps :
    jobState[d] = "done" =>
      (<<d, jobContent[d]>> \in serverReports) \/ serverDump[d] = "purged"

\* A purged dump holds no reports (cascade) and accepts no new ones
\* (SubmitAccept requires available).
PurgedDumpHasNoReports ==
  \A d \in Dumps :
    serverDump[d] = "purged" => {r \in serverReports : r[1] = d} = {}

=============================================================================
