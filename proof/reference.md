# MCP Behavior assessment

Overall: **INCOMPLETE**

Readiness: **PASS**  
Security: **INCOMPLETE**  

Finite Linux stdio, synchronous, read-only repository profile; not protocol conformance or a general security certification.

| Check | Lane | Result | Evidence / reason |
|---|---|---|---|
| normal.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| normal.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| normal.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| normal.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| normal.honest_completion | readiness | PASS | completion status agrees with the observed work |
| normal.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| missing.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| missing.error_reason | readiness | PASS | bad input needs an error identifying the input and its cause |
| recovery.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| recovery.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| recovery.honest_completion | readiness | PASS | completion status agrees with the observed work |
| missing.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| file_as_root.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| file_as_root.error_reason | readiness | PASS | bad input needs an error identifying the input and its cause |
| file_as_root.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| relative.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| relative.path_boundary | security | PASS | out-of-contract paths require an explicit, reasoned refusal |
| relative.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| outside.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| outside.path_boundary | security | PASS | out-of-contract paths require an explicit, reasoned refusal |
| outside.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| traversal.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| traversal.path_boundary | security | PASS | out-of-contract paths require an explicit, reasoned refusal |
| traversal.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| escaping_symlink.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| escaping_symlink.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| escaping_symlink.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| escaping_symlink.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| escaping_symlink.honest_completion | readiness | PASS | completion status agrees with the observed work |
| escaping_symlink.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| escaping_symlink.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| dangling_symlink.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| dangling_symlink.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| dangling_symlink.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| dangling_symlink.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| dangling_symlink.honest_completion | readiness | PASS | completion status agrees with the observed work |
| dangling_symlink.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| dangling_symlink.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| internal_symlink.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| internal_symlink.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| internal_symlink.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| internal_symlink.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| internal_symlink.honest_completion | readiness | PASS | completion status agrees with the observed work |
| internal_symlink.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| internal_symlink.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| directory_loop.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| directory_loop.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| directory_loop.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| directory_loop.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| directory_loop.honest_completion | readiness | PASS | completion status agrees with the observed work |
| directory_loop.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| directory_loop.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| special_file.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| special_file.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| special_file.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| special_file.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| special_file.honest_completion | readiness | PASS | completion status agrees with the observed work |
| special_file.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| special_file.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| unreadable.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| unreadable.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| unreadable.coverage | readiness | PASS | all fixture inputs independently reconcile with disjoint evidence records |
| unreadable.content_correctness | readiness | PASS | file digests match independent fixture bytes |
| unreadable.honest_completion | readiness | PASS | completion status agrees with the observed work |
| unreadable.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| unreadable.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| large.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| large.bounded_output | readiness | PASS | stress request was explicitly refused for size |
| large.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| normal_fresh.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| repeatability | readiness | PASS | same and fresh sessions produced equivalent evidence |
| scripted_recovery | readiness | PASS | bounded recovery requires a useful missing-input error and an independently correct repaired request |
| tool_surface_stability | readiness | PASS | tool-definition fingerprint must stay fixed across this profile&#x27;s sessions |
| artifact_stability | security | PASS | configured artifact bytes stayed fixed |
| execution_containment | security | UNKNOWN | native subprocess mode does not isolate host files, network, same-UID processes, or escaped descendants |
| real_model_recovery | agent_run | N/A | real-model runs are outside v1 and never substitute for fixture grades |

## Assessment identity

```json
{
  "target": {
    "reviewer_declared": {
      "name": "reference-inventory",
      "version": "0.1.0"
    },
    "command_sha256": "6849f9325f04866dbddd85a4dd441382d5ac8f8a4b6125065802defe4b857715",
    "artifacts": [
      {
        "path": "/workspace/scratch/2c2f33936de9/mcp-behavior/examples/reference_server.py",
        "sha256": "ab78139ec7ce9628cca9438db30ace50ae56defa8999e65da2c6daac36e3c7e0",
        "bytes": 7210
      },
      {
        "path": "/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12",
        "sha256": "fa67443527ed9647f760d807e2a38f26340757123e643c4639cf273ed15d5ea7",
        "bytes": 30894944
      }
    ],
    "scope": "Explicit files and executable only; dependency closure is not attested."
  },
  "profile": {
    "id": "readonly-repository",
    "version": "1.0.0",
    "sha256": "bbe5d5b546a259c2087e9c317baff464ece34f01ca7721daa898fb2c707b036d",
    "tool": "inspect_repository",
    "supported_suffixes": [
      ".py",
      ".js",
      ".txt"
    ],
    "relative_paths": "reject"
  },
  "config_sha256": "15e7e887b1244f677f2dcf8e042b3a630fcdc53485cd529e92bb35d5fa965c0e",
  "limits": {
    "timeout_seconds": 5,
    "case_timeout_seconds": 30.0,
    "suite_timeout_seconds": 180.0,
    "max_frame_bytes": 262144,
    "max_result_bytes": 65536,
    "max_session_bytes": 4194304,
    "max_stderr_bytes": 65536,
    "max_messages": 256,
    "memory_mib": 512,
    "cpu_seconds": 20
  }
}
```

## Limits on the conclusion

- Native mode cannot certify containment or absence of unobserved host effects.
- Snapshots do not prove absence of transient writes or reads that leave no observable evidence.
- Artifact identity covers explicit files, not the installed dependency closure.
- Behavioral field mappings and expected capabilities are reviewer-owned assertions; review their digest.
- A PASS applies only to the named tool, fixtures, profile, limits, and configuration.
- Content hashes verify the inventory profile, not the semantic accuracy of a vulnerability scanner.
