# Hardened M365 Password Reset Tool

PowerShell GUI tool for staged Microsoft 365 password resets with defensive preflight checks, configurable mail sender settings, and configurable workflow timers.

Current QA build documented here:
- `O365_BatchUserPw.ps1`

## What it does

This tool is built for the following operator-controlled workflow:

1. Generate a temporary password
2. Email that password to the user
3. Wait a configurable delay
4. Apply the password to the account
5. Force the user to change it at next sign-in

The script is intentionally opinionated about safety:
- it performs strict preflight checks before running the workflow
- it verifies Graph scopes needed for user read/write, password profile write, and delegated mail send
- it blocks bad or incomplete configuration early
- it logs each major step and writes a CSV processing report
- it attempts to avoid sending a password email when the session cannot actually complete the reset
- it can send a correction / invalidation notice if email succeeded but password application later failed

## Key features

### GUI configuration
- Configurable **Send As address**
- Configurable **activation delay**
- Configurable **retry delay**
- Configurable **SMTP wait**
- Visible workflow summary in the header
- Status area and color-coded log output

### Workflow protection
- Strict preflight mode
- Required-scope validation
- Delegated send validation when sending from a mailbox different from the authenticated admin account
- Password-reset capability validation before processing
- Retry logic for transient Graph failures
- Graceful handling when sign-in activity cannot be read
- Password policy regeneration flow when a generated password is rejected

### Logging and output
- Rolling log file under the configured log directory
- Per-run CSV report
- Row status updates in the grid during processing

## Current default configuration

These are the defaults in the current QA build:

- Domain: `allwavesites.com`
- Authenticated Graph account: `admin@NETORG500158.onmicrosoft.com`
- Default Send As address: `user@domain.com`
- Default support email: `user@domain.com`
- Activation delay: `20` seconds
- Retry delay: `2` seconds
- SMTP wait: `15` seconds
- Log path: `C:\temp\allwavesites_pwreset_logs`

## Required PowerShell / environment

Recommended environment:
- Windows PowerShell 5.1 or PowerShell 7+
- Interactive sign-in available for Microsoft Graph
- WinForms-capable Windows session
- Permission to write logs to the configured log path or fallback temp/desktop paths

The script uses:
- `System.Windows.Forms`
- `System.Drawing`
- `System.Web`
- Microsoft Graph PowerShell modules available in the operator environment

## Required Graph scopes expected by the script

The current script treats these as required:

- `User.Read.All`
- `User.ReadWrite.All`
- `User-PasswordProfile.ReadWrite.All`
- `Directory.Read.All`
- `Directory.ReadWrite.All`
- `Mail.Send`

Optional:
- `AuditLog.Read.All`

Additional delegated send behavior:
- if the configured **Send As** address is different from the authenticated Graph account, the script also expects `Mail.Send.Shared`

## High-level workflow logic

### Preflight
Before processing users, the script attempts to verify:
- Graph connection exists and matches the expected authenticated account
- required scopes are present
- delegated send scope is present when needed
- configuration values are valid
- runtime paths are writable
- reset-capable conditions are met before any password email is sent

### Per-user flow
For each selected user, the tool attempts to:
1. Validate row data and target account details
2. Generate a temporary password
3. Send the password email using Graph first
4. Wait for the configured activation delay
5. Apply the password profile to the account
6. Mark the account to force password change at next sign-in
7. Record the outcome in logs and CSV report

### Fallback / compensation behavior
The tool also contains logic for:
- reconnecting Graph after certain failures
- SMTP fallback as a last resort when explicitly allowed
- retrying failed operations within configured retry limits
- regenerating and correcting passwords when policy rejects the generated value
- sending an “Ignore Previous Password Email” correction message if mail went out but password application failed later

## Top probable failure scenarios the script is designed to handle

1. Wrong Microsoft Graph account signed in
2. Missing required Graph scopes
3. Missing delegated mail-send capability for alternate sender mailbox
4. Graph throttling or transient network failures
5. Token/session expiration during a run
6. Password policy rejection of generated password
7. Sign-in activity read blocked or forbidden
8. Invalid or stale saved GUI config values
9. Log/report path not writable
10. Target row issues such as deleted users, bad addresses, or mailbox problems

## GUI notes

### Sender field
The **Send As address** is now configurable from the GUI so the same tool can be reused across different tenants or sender mailboxes.

Default value:
- `user@domain.com`

### Timer fields
The GUI exposes three timer controls:
- **Apply delay (sec)**: how long to wait after email before applying the password
- **Retry delay (sec)**: delay between retries for Graph operations
- **SMTP wait (sec)**: delay used for SMTP fallback timing / propagation handling

The script clamps loaded config values into safe numeric ranges so older saved settings do not crash the form.

## Important operational notes

- The workflow email is intended to be sent **before** the password is applied.
- Because of that design, a very short activation delay can create a race where the password becomes active before the user sees the email.
- The default delay is currently **20 seconds** in this QA build.
- Sent mail visibility may depend on whether mail was sent through the authenticated admin mailbox with a delegated `from` address and where the tenant stores Sent Items copies.
- The script logs when sign-in activity cannot be retrieved and continues without it.

## Running the script

Example:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\hardened_m365_pwreset_tool_QA_v8_generic_sendas_default.ps1
```

Recommended operator flow:
1. Launch the script
2. Connect to Graph with the intended admin account
3. Confirm the expected scopes are granted
4. Set the Send As address
5. Set the timers
6. Load users
7. Select pilot users first
8. Run a controlled test before bulk processing
9. Review the generated CSV report and log file

## Files produced

The tool writes output under the configured log directory, typically:

- daily log file such as `reset_YYYYMMDD.log`
- per-run CSV report such as `report_YYYYMMDD_HHMMSS.csv`

If the configured log path is not writable, the script attempts fallback locations.

## QA checklist

Before wider rollout, verify:
- GUI opens without config-load errors
- Send As address validation works
- Timer values save/load cleanly
- Graph sign-in uses the intended admin account
- required scopes are present
- delegated send works with the chosen sender mailbox
- a test user receives the email
- password is actually applied after the configured delay
- correction notice sends if the apply step is forced to fail
- CSV and log files are written successfully

## Known limitations / cautions

- If the environment lacks the right Graph privileges, the workflow should now fail early, but tenant-side role limitations can still block target resets.
- Sign-in activity may be unavailable even when the rest of the workflow functions.
- SMTP fallback is last-resort behavior and should not be treated as the primary transport.
- Very aggressive delay values increase the chance of user confusion.

## Suggested next documentation items

Good follow-up files to add alongside this README:
- `CHANGELOG.md`
- `QA_TEST_PLAN.md`
- `KNOWN_ISSUES.md`
- `TENANT_SETUP.md`

