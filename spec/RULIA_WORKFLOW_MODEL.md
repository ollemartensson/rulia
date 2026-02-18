# Rulia Workflow Model

## Scope
Rulia defines workflow semantics as deterministic orchestration over canonical artifacts.
Workflows are data, not executable source code.

## EvalIR Concept
Rulia defines EvalIR as the canonical intermediate representation of workflow intent.
EvalIR contains:
- Step declarations.
- Data dependencies.
- Control dependencies.
- Suspension and resumption points.
- Completion criteria.

EvalIR is canonical data and is hashable under core rules.

## Steps
Rulia defines a step as a deterministic state transition over explicit inputs.
A step:
- Consumes declared artifacts only.
- Produces declared artifacts only.
- Emits obligations when evidence is required.

Rulia requires step semantics to be pure with respect to workflow state.
Any side effect request is represented as protocol intent, not inline execution.

## Branching
Rulia defines branching as deterministic path selection from explicit predicate inputs.

Rulia requires:
- Branch predicates to reference canonical artifacts only.
- Predicate evaluation to produce one deterministic branch result.
- Branch outcomes to be represented as artifacts.

## Joins
Rulia defines joins as deterministic merge points over named predecessor outputs.

Rulia requires:
- Join readiness criteria to be explicit.
- Join merge logic to be canonical and deterministic.
- Missing predecessor artifacts to surface as explicit incomplete state.

## Suspension and Resumption
Rulia defines suspension as a first-class workflow state where progress awaits external artifacts.

Rulia requires:
- Suspension reason and required artifacts to be explicit.
- Resumption to consume only declared new artifacts.
- Resumption to continue from a canonical checkpoint state.

## Deterministic Execution Rules
Rulia requires workflow evaluation to depend only on:
- EvalIR.
- Declared input artifacts.
- Prior canonical workflow state.
- Declared protocol evidence.

Rulia forbids hidden dependency on host clocks, ambient randomness, or undeclared IO in workflow semantics.

## Why Workflows Are Data
Rulia defines workflows as data so every state transition is inspectable, hashable, and replayable.
This enables independent verification and language-neutral execution.

## Why Workflows Always Halt
Rulia defines workflow structure to guarantee halting:
- EvalIR step graph is finite.
- Control flow does not permit unbounded self-expansion.
- Repetition, if present, must be bounded by explicit finite counters or finite artifact sets.
- Suspension terminates active computation until new artifacts arrive.

Rulia guarantees each evaluation run reaches either Completed, Failed, or Suspended state in finite steps.

## Why Workflows Are Replayable
Rulia guarantees replayability because workflow state transitions are deterministic and artifact-driven.
Given identical EvalIR and identical artifact history, replay yields identical state sequence and outcome.
