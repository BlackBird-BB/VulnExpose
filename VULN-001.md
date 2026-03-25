# VULN-001 — SSH Credentials Exposed via Command-Line Arguments

**CWE:** CWE-214 (Invocation of Non-Repudiable Function) / CWE-522 (Insufficiently Protected Credentials)

`--password`, `--sudoPassword`, `--suPassword` are passed as command-line arguments. Any local user can read them via `ps aux`, `/proc/<pid>/cmdline`.

**Location:** `src/index.ts:6-16` (parseArgv), `src/index.ts:17-21`

**Attack:**
```bash
ps aux | grep ssh-mcp
# --password=MySecret --sudoPassword=SudoPass --suPassword=RootPass fully visible
```

**Note:** Reported separately in `ssh-mcp-credential-exposure.md`.