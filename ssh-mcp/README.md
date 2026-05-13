# ssh-mcp vuln unsolicited disclosure

> SSH MCP Server (tufantunc/ssh-mcp) — Full Security Audit Report

## Project Info

- **Repository:** https://github.com/tufantunc/ssh-mcp
- **Version:** 1.5.0
- **NPM:** ssh-mcp
- **Language:** TypeScript
- **Dependencies:** @modelcontextprotocol/sdk, ssh2, zod
- **Audit Date:** 2026-03-21

---

## VULN-001 — SSH Credentials Exposed via Command-Line Arguments

**CWE:** CWE-214 (Invocation of Non-Repudiable Function) / CWE-522 (Insufficiently Protected Credentials)

`--password`, `--sudoPassword`, `--suPassword` are passed as command-line arguments. Any local user can read them via `ps aux`, `/proc/<pid>/cmdline`.

**Location:** `src/index.ts:6-16` (parseArgv), `src/index.ts:17-21`

**Attack:**
```bash
ps aux | grep ssh-mcp
# --password=MySecret --sudoPassword=SudoPass --suPassword=RootPass fully visible
```

**Note:** Reported separately in `ssh-mcp-credential-exposure.md`.

---

## VULN-002 — Sudo Password Exposed in Remote Server Process List

**CWE:** CWE-522 (Insufficiently Protected Credentials)

The `sudoPassword` is embedded directly into the command string sent to the remote SSH server via `conn.exec()`. Since SSH's exec request goes through `/bin/sh -c` on the remote server, the sudo password appears in the remote process's command line.

**Location:** `src/index.ts:478-481`

**Vulnerable Code:**
```typescript
const pwdEscaped = sudoPassword.replace(/'/g, "'\\''");
wrapped = `printf '%s\\n' '${pwdEscaped}' | sudo -p "" -S sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
return await execSshCommandWithConnection(connectionManager, wrapped);
```

**Attack Scenario:**

1. User configures ssh-mcp with `--sudoPassword=MySudoPass123`
2. MCP client invokes `sudo-exec` with any command
3. The following string is sent to the remote server's shell:
   ```
   printf '%s\n' 'MySudoPass123' | sudo -p "" -S sh -c 'ls'
   ```
4. Any user on the **remote** server can now read the sudo password:
   ```bash
   # On the remote server:
   ps aux | grep printf
   # Shows: printf '%s\n' 'MySudoPass123' | sudo -p "" -S sh -c 'ls'
   
   cat /proc/$(pgrep -f "printf.*sudo")/cmdline | tr '\0' ' '
   # Shows the full command including the plaintext password
   ```

**Impact:**
- Sudo password leaked to any user on the remote server
- Process accounting (`lastcomm`, `acct`, `auditd`) may log the password
- Password persists in logs and audit trails
- Combined with VULN-001, both local and remote credentials are exposed

**Fix:** Use SSH channel stdin to pipe the password instead of embedding it in the command:
```typescript
conn.exec(`sudo -p "" -S sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`, (err, stream) => {
  stream.write(sudoPassword + '\n');
  stream.end();
  // ... read output
});
```

---

## VULN-003 — su Shell Command Injection

When the su shell is active, commands are written directly to an interactive shell session via `shell.write()`. The `description` parameter is appended to the command and only has `#` characters escaped. Newlines in the description allow injecting additional commands that execute as root.

**Location:** `src/index.ts:402-404` (exec tool), `src/index.ts:475-477` (sudo-exec tool), `src/index.ts:540` (shell.write)

**Vulnerable Code (exec tool):**
```typescript
const commandWithDescription = description
  ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
  : sanitizedCommand;
// ...
shell.write(command + '\n');  // In execSshCommandWithConnection when su shell is active
```

**Wait — `shell.write(command + '\n')`** uses the unwrapped `command`, not `commandWithDescription`... let me verify.

Actually looking at line 540: `shell.write(command + '\n');` — the `command` parameter passed to `execSshCommandWithConnection` IS `commandWithDescription`.

**Attack Scenario:**

1. User (or LLM) calls the `exec` MCP tool with:
   ```json
   {
     "command": "ls",
     "description": "list files\nuseradd hacker\npasswd hacker"
   }
   ```

2. `sanitizeCommand("ls")` returns `"ls"` (passes validation)
3. `description.replace(/#/g, '\\#')` does NOT filter newlines
4. `commandWithDescription` = `"ls # list files\nuseradd hacker\npasswd hacker"`
5. `execSshCommandWithConnection(manager, commandWithDescription)` is called
6. Since su shell is active, the code does: `shell.write("ls # list files\nuseradd hacker\npasswd hacker\n")`
7. The interactive root shell receives:
   ```bash
   ls # list files
   useradd hacker
   passwd hacker
   ```
8. Three commands execute as root: `ls`, `useradd hacker`, `passwd hacker`

**Impact:**
- Arbitrary root command execution via description field injection
- The description field appears innocuous in MCP logs
- Only works when su shell is active (--suPassword is set)

**Fix:** Sanitize the description to remove or escape newlines and other shell metacharacters:
```typescript
const safeDescription = description.replace(/[\n\r]/g, ' ').replace(/#/g, '\\#');
```

## Credits

Discovered by BlackBird-BB, 2026-03-21.
