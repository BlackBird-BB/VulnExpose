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