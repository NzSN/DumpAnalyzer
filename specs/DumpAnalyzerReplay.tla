------------------------ MODULE DumpAnalyzerReplay ------------------------
EXTENDS DumpAnalyzer

\* Witness target for per-action traces: the cfg assigns the action name whose
\* first occurrence violates NeverTarget (TLC config CONSTANT assignment).
\* "" disables the per-action witness (completion runs only).
CONSTANT TargetAction

\* Replay/trace-generation profile for the base DumpAnalyzer model
\* (specs/DumpAnalyzer.tla). No behavior changes; this module adds the view
\* and the completion witness used to extract traces for MirrorRust replay
\* (tests/mbt). The name TraceComplete follows the Mirrors convention: its
\* violation is the counterexample that becomes the replay trace.

\* Variables that define a behavior's shape for dedup; the full state is
\* recorded in traces.
View == <<jobState, jobContent, bytesVerified, attempts, serverDump, agentUp,
          eventCursor>>

\* Terminal job phases; "none" is not terminal (no job ever existed).
TerminalPhases == {"done", "dropped", "failed"}

\* Holds initially (every slot is "none"); a violation witnesses every dump
\* slot terminally settled — the shortest witness is the happy-path trace,
\* longer/variant witnesses carry crashes, purges, and retries.
TraceComplete == ~(\A d \in Dumps : jobState[d] \in TerminalPhases)

\* Holds until the named action first fires; a violation yields the shortest
\* trace executing that action. Per-action witnesses give deterministic
\* coverage that random simulation cannot reach reliably (deep pipeline
\* stages lose the race against purge/crash in simulation).
NeverTarget == action_taken /= TargetAction

=============================================================================
