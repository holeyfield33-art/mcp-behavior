# MCP Behavior assessment

Overall: **FAIL**

Readiness: **FAIL**  
Security: **FAIL**  

Finite Linux stdio, synchronous, read-only repository profile; not protocol conformance or a general security certification.

| Check | Lane | Result | Evidence / reason |
|---|---|---|---|
| normal.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| normal.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| normal.coverage | readiness | FAIL | fixture files were omitted, failed, or replaced by unexpected records |
| normal.content_correctness | readiness | UNKNOWN | no content oracle mapping; file enumeration does not prove scanner finding correctness |
| normal.honest_completion | readiness | UNKNOWN | completion evidence is not mapped |
| normal.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| missing.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| missing.error_reason | readiness | FAIL | bad input needs an error identifying the input and its cause |
| missing.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| file_as_root.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| file_as_root.error_reason | readiness | FAIL | bad input needs an error identifying the input and its cause |
| file_as_root.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| relative.wire_canary | security | FAIL | wire result disclosed an outside/CWD decoy canary |
| relative.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| relative.path_boundary | security | FAIL | out-of-contract paths require an explicit, reasoned refusal |
| relative.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| outside.wire_canary | security | FAIL | wire result disclosed an outside/CWD decoy canary |
| outside.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| outside.path_boundary | security | FAIL | out-of-contract paths require an explicit, reasoned refusal |
| outside.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| traversal.wire_canary | security | FAIL | wire result disclosed an outside/CWD decoy canary |
| traversal.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| traversal.path_boundary | security | FAIL | out-of-contract paths require an explicit, reasoned refusal |
| traversal.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| escaping_symlink.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| escaping_symlink.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| escaping_symlink.coverage | readiness | FAIL | fixture files were omitted, failed, or replaced by unexpected records |
| escaping_symlink.content_correctness | readiness | UNKNOWN | no content oracle mapping; file enumeration does not prove scanner finding correctness |
| escaping_symlink.honest_completion | readiness | UNKNOWN | completion evidence is not mapped |
| escaping_symlink.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| escaping_symlink.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| dangling_symlink.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| dangling_symlink.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| dangling_symlink.coverage | readiness | FAIL | fixture files were omitted, failed, or replaced by unexpected records |
| dangling_symlink.content_correctness | readiness | UNKNOWN | no content oracle mapping; file enumeration does not prove scanner finding correctness |
| dangling_symlink.honest_completion | readiness | UNKNOWN | completion evidence is not mapped |
| dangling_symlink.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| dangling_symlink.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| internal_symlink.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| internal_symlink.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| internal_symlink.coverage | readiness | FAIL | fixture files were omitted, failed, or replaced by unexpected records |
| internal_symlink.content_correctness | readiness | UNKNOWN | no content oracle mapping; file enumeration does not prove scanner finding correctness |
| internal_symlink.honest_completion | readiness | UNKNOWN | completion evidence is not mapped |
| internal_symlink.boundary_refusal | security | FAIL | unsafe or unreadable entries require an explicit refusal and reason |
| internal_symlink.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| directory_loop.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| directory_loop.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| directory_loop.coverage | readiness | FAIL | fixture files were omitted, failed, or replaced by unexpected records |
| directory_loop.content_correctness | readiness | UNKNOWN | no content oracle mapping; file enumeration does not prove scanner finding correctness |
| directory_loop.honest_completion | readiness | UNKNOWN | completion evidence is not mapped |
| directory_loop.boundary_refusal | security | FAIL | unsafe or unreadable entries require an explicit refusal and reason |
| directory_loop.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| special_file.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| special_file.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| special_file.coverage | readiness | FAIL | fixture files were omitted, failed, or replaced by unexpected records |
| special_file.content_correctness | readiness | UNKNOWN | no content oracle mapping; file enumeration does not prove scanner finding correctness |
| special_file.honest_completion | readiness | UNKNOWN | completion evidence is not mapped |
| special_file.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| special_file.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| unreadable.output_budget | readiness | PASS | observed tool reply stayed within the profile&#x27;s wire byte limit |
| unreadable.canary | security | PASS | no outside/CWD decoy canary was disclosed |
| unreadable.coverage | readiness | FAIL | fixture files were omitted, failed, or replaced by unexpected records |
| unreadable.content_correctness | readiness | UNKNOWN | no content oracle mapping; file enumeration does not prove scanner finding correctness |
| unreadable.honest_completion | readiness | UNKNOWN | completion evidence is not mapped |
| unreadable.boundary_refusal | security | PASS | unsafe or unreadable entries require an explicit refusal and reason |
| unreadable.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| large.bounded_output | readiness | FAIL | server exceeded the frame byte limit before a newline or JSON decoding |
| large.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| normal_fresh.read_only | security | PASS | observable bytes, entries, permissions, and modification metadata stayed fixed |
| repeatability | readiness | PASS | same and fresh sessions produced equivalent evidence |
| scripted_recovery | readiness | FAIL | bounded recovery requires a useful missing-input error and an independently correct repaired request |
| tool_surface_stability | readiness | PASS | tool-definition fingerprint must stay fixed across this profile&#x27;s sessions |
| artifact_stability | security | PASS | configured artifact bytes stayed fixed |
| execution_containment | security | UNKNOWN | native subprocess mode does not isolate host files, network, same-UID processes, or escaped descendants |
| real_model_recovery | agent_run | N/A | real-model runs are outside v1 and never substitute for fixture grades |

## Assessment identity

```json
{
  "target": {
    "reviewer_declared": {
      "name": "Sentinel-Zero external test subject",
      "version": "git:303267e4786735b068ed544936480b2368194b01"
    },
    "command_sha256": "08d1e01cb81ae8bf753300faf2d804d64288a51774529a44bf9c842bc728df15",
    "artifacts": [
      {
        "path": "/workspace/scratch/2c2f33936de9/code-sentinel/pyproject.toml",
        "sha256": "3644279d4dc1e0bafec6b70420b32c1a8e845ccc582e9493a8298bcc5ef996cd",
        "bytes": 1109
      },
      {
        "path": "/workspace/scratch/2c2f33936de9/code-sentinel/sentinel_zero/mcp_server.py",
        "sha256": "698e235859b8e3ac3309c884aaa11eb1016dfd3cfb14a182669165c41645deba",
        "bytes": 4621
      },
      {
        "path": "/workspace/scratch/2c2f33936de9/code-sentinel/sentinel_zero/dogfood_scan.py",
        "sha256": "0af23c0ebdefcf7cfdd9a3f0536ddbc72bc35e8903423574d26745795cf13110",
        "bytes": 48824
      },
      {
        "path": "/workspace/scratch/2c2f33936de9/code-sentinel/sentinel_zero/resolvers/python_resolver.py",
        "sha256": "421acc21f2e6379f4a090a4c1d860055a6b356222a993e41d6e0e505f07ebebf",
        "bytes": 66081
      },
      {
        "path": "/workspace/scratch/2c2f33936de9/code-sentinel/sentinel_zero/repo_detect.py",
        "sha256": "3cc5904d0593973f694038e27df750d4b74ee91fdbdb855047920f7bb91ce468",
        "bytes": 1902
      },
      {
        "path": "/workspace/scratch/2c2f33936de9/code-sentinel/sentinel_zero/source_inputs.py",
        "sha256": "4fef08533cfe463f52041b849ebc203a316eb2b0f17f391add458cc331545aa8",
        "bytes": 2362
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
    "id": "readonly-repository-scanner-observation",
    "version": "1.0.0",
    "sha256": "6eb8a47fcfb835d0902a9396512bcfe199c851ba082ef8bf25f8ebe351755371",
    "tool": "analyze_repository",
    "supported_suffixes": [
      ".py",
      ".js"
    ],
    "relative_paths": "reject"
  },
  "config_sha256": "691d68cbc3b6148edf523395ecb4bc5a4cb237b44ca48e69baa060a7e6677c37",
  "limits": {
    "timeout_seconds": 15,
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
