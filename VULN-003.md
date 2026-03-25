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