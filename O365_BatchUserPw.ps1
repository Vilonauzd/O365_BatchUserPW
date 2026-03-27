<#
.SYNOPSIS
    Hardened Microsoft 365 Password Reset Tool with GUI + Password Tracking
.DESCRIPTION
    Bulk temporary-password workflow for Microsoft 365 users with defensive logic.

    Intended flow per operator requirement:
      1. Generate temporary password
      2. Email temporary password to user
      3. Wait $($Config.PropagationWaitSeconds) seconds
      4. Apply that password to the account and force change at next sign-in

    Hardening added for common failure scenarios:
      - Wrong Graph account connected
      - Missing Graph scopes (including Mail.Send.Shared when sending as another mailbox)
      - Legacy SMTP Basic auth deprecation / fallback only when explicitly needed
      - Send As / Send on Behalf failures
      - Graph throttling / transient network failures
      - Token expiry or stale session mid-run
      - Password policy rejection / banned password compensation flow
      - UI freeze during wait / retry loops
      - Unwritable log path / export path issues
      - Invalid row data / deleted user / mailbox issues
#>

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch {}

# ====================== CONFIGURATION ======================
$Config = @{
    Domain = "domain.com"

    # Interactive Graph sign-in is expected to use this account.
    AuthenticatedGraphAccount = "user@domain.com"

    # The mailbox address the message should appear from.
    MailFrom = "user@domain.com"

    # SMTP fallback is last-resort only. Credentials are for the authenticating account,
    # not necessarily the visible From address.
    SmtpAuthUser = "user@domain.com"
    SmtpServer = "smtp.office365.com"
    SmtpPort = 587
    AllowLegacySmtpFallback = $true
    TryEnableSmtpAuthOnFallback = $true

    PropagationWaitSeconds = 20
    SupportEmail = "user@domain.com"
    SupportPhone = "[Your Support Phone]"
    LogPath = "C:\temp\O365_BatchUserPW"

    GraphRetryCount = 3
    PasswordApplyRetryCount = 3
    PasswordRegenerationAttempts = 2
    GraphRetryDelaySeconds = 2
    SmtpAuthPropagationWaitSeconds = 15

    RequiredScopes = @(
        "User.Read.All",
        "User.ReadWrite.All",
        "User-PasswordProfile.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "Mail.Send"
    )

    StrictPreflight = $true

    OptionalScopes = @(
        "AuditLog.Read.All"
    )
}

# ====================== LOAD ASSEMBLIES ======================
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Web
    [System.Windows.Forms.Application]::EnableVisualStyles()
}
catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load required .NET assemblies.`n`n$($_.Exception.Message)",
        "Critical Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

# ====================== GLOBAL VARIABLES ======================
$Script:GraphConnected = $false
$Script:ExchangeConnected = $false
$Script:UsersLoaded = $false
$Script:ProcessingResults = @()
$Script:PasswordRecords = @()
$Script:SmtpCredentials = $null
$Script:Form = $null
$Script:StatusLabel = $null
$Script:LogBox = $null
$Script:DataGridView = $null
$Script:CurrentRowIndex = 0
$Script:ResolvedLogPath = $null
$Script:MailFromTextBox = $null
$Script:AuthenticatedGraphAccountTextBox = $null

# ====================== UTILITY FUNCTIONS ======================
function Test-IsAdministrator {
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Ensure-Directory {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        return $true
    }
    catch {
        return $false
    }
}

function Resolve-LogPath {
    $candidatePaths = @(
        $Config.LogPath,
        (Join-Path -Path $env:TEMP -ChildPath "O365_BatchUserPW"),
        (Join-Path -Path ([Environment]::GetFolderPath('Desktop')) -ChildPath "O365_BatchUserPW")
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($path in $candidatePaths) {
        if (Ensure-Directory -Path $path) {
            return $path
        }
    }

    return $null
}

$Script:ResolvedLogPath = Resolve-LogPath

function Pump-UI {
    try {
        [System.Windows.Forms.Application]::DoEvents()
    }
    catch {}
}

function Wait-WithUi {
    param(
        [int]$Seconds,
        [string]$Prefix = "Waiting"
    )

    for ($i = $Seconds; $i -gt 0; $i--) {
        Update-Status "$Prefix $i second(s)..."
        Pump-UI
        Start-Sleep -Seconds 1
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info",
        [bool]$WriteToConsole = $true
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"

    try {
        if ($Script:LogBox -and -not $Script:LogBox.IsDisposed) {
            $color = switch ($Type) {
                "Success" { [System.Drawing.Color]::LightGreen }
                "Error"   { [System.Drawing.Color]::LightCoral }
                "Warning" { [System.Drawing.Color]::Khaki }
                default     { [System.Drawing.Color]::White }
            }

            $Script:LogBox.SelectionColor = $color
            $Script:LogBox.AppendText("$logEntry`n")
            $Script:LogBox.ScrollToCaret()
            Pump-UI
        }
    }
    catch {}

    if ($WriteToConsole) {
        switch ($Type) {
            "Success" { Write-Host $logEntry -ForegroundColor Green }
            "Error"   { Write-Host $logEntry -ForegroundColor Red }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            default    { Write-Host $logEntry }
        }
    }

    try {
        if ($Script:ResolvedLogPath) {
            $logFile = Join-Path -Path $Script:ResolvedLogPath -ChildPath ("reset_{0}.log" -f (Get-Date -Format 'yyyyMMdd'))
            Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
        }
    }
    catch {}
}

function Update-Status {
    param([string]$Message)

    try {
        if ($Script:StatusLabel -and -not $Script:StatusLabel.IsDisposed) {
            $Script:StatusLabel.Text = "📡 Status: $Message"
            if ($Script:Form -and -not $Script:Form.IsDisposed) {
                $Script:Form.Refresh()
            }
            Pump-UI
        }
    }
    catch {}
}

function Set-RowStatus {
    param(
        [Parameter(Mandatory = $true)]$Row,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][System.Drawing.Color]$Color
    )

    try {
        $Row.Cells["Status"].Value = $Status
        $Row.DefaultCellStyle.BackColor = $Color
        Pump-UI
    }
    catch {}
}


function Get-ConditionalText {
    param(
        [bool]$Condition,
        [string]$TrueText,
        [string]$FalseText
    )

    if ($Condition) { return $TrueText }
    return $FalseText
}

function Mask-Password {
    param([string]$Password)

    if ([string]::IsNullOrWhiteSpace($Password)) { return "" }
    return ("•" * [Math]::Min($Password.Length, 10))
}

function Test-ValidEmailAddress {
    param([string]$Address)

    try {
        if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
        $null = [System.Net.Mail.MailAddress]::new($Address)
        return $true
    }
    catch {
        return $false
    }
}

function Ensure-NuGetProvider {
    try {
        $nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
        if (-not $nuget) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        }
        return $true
    }
    catch {
        Write-Log "Failed to prepare NuGet provider: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Ensure-Module {
    param([string]$Name)

    try {
        if (Get-Module -ListAvailable -Name $Name) {
            return $true
        }

        Write-Log "Module '$Name' is missing. Attempting install for CurrentUser..." "Warning"

        if (-not (Ensure-NuGetProvider)) {
            return $false
        }

        try {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
        }
        catch {}

        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Log "Installed module '$Name' successfully." "Success"
        return $true
    }
    catch {
        Write-Log "Failed to install module '$Name': $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-GraphRequiredScopes {
    $scopes = @($Config.RequiredScopes)

    if (
        -not [string]::IsNullOrWhiteSpace($Config.MailFrom) -and
        -not [string]::IsNullOrWhiteSpace($Config.AuthenticatedGraphAccount) -and
        ($Config.MailFrom.Trim().ToLowerInvariant() -ne $Config.AuthenticatedGraphAccount.Trim().ToLowerInvariant())
    ) {
        $scopes += "Mail.Send.Shared"
    }

    return @($scopes | Sort-Object -Unique)
}

function Get-CurrentGraphContext {
    try {
        return Get-MgContext -ErrorAction SilentlyContinue
    }
    catch {
        return $null
    }
}

function Has-GraphScope {
    param([string]$Scope)

    $context = Get-CurrentGraphContext
    if (-not $context -or -not $context.Scopes) { return $false }

    foreach ($existingScope in $context.Scopes) {
        if ($existingScope -and ($existingScope.Trim().ToLowerInvariant() -eq $Scope.Trim().ToLowerInvariant())) {
            return $true
        }
    }

    return $false
}

function Test-GraphScopes {
    param([string[]]$Scopes)

    foreach ($scope in $Scopes) {
        if (-not (Has-GraphScope -Scope $scope)) {
            return $false
        }
    }

    return $true
}

function Disconnect-Graph {
    try {
        if ($Script:GraphConnected) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Log "Disconnected from Microsoft Graph" "Info"
            $Script:GraphConnected = $false
        }
    }
    catch {
        Write-Log "Error during Graph disconnect: $($_.Exception.Message)" "Warning"
    }
}

function Validate-GraphAccount {
    $context = Get-CurrentGraphContext
    if (-not $context -or -not $context.Account) { return $false }

    if ([string]::IsNullOrWhiteSpace($Config.AuthenticatedGraphAccount)) {
        return $true
    }

    $expected = $Config.AuthenticatedGraphAccount.Trim().ToLowerInvariant()
    $actual = $context.Account.Trim().ToLowerInvariant()

    if ($actual -eq $expected) {
        return $true
    }

    Write-Log "Connected Graph account '$($context.Account)' does not match expected account '$($Config.AuthenticatedGraphAccount)'." "Warning"

    $continue = [System.Windows.Forms.MessageBox]::Show(
        "Connected Graph account:`n$($context.Account)`n`nExpected account:`n$($Config.AuthenticatedGraphAccount)`n`nContinue anyway?`n`nChoosing 'No' will disconnect Graph so you can reconnect with the intended account.",
        "Graph Account Mismatch",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($continue -eq [System.Windows.Forms.DialogResult]::No) {
        Disconnect-Graph
        return $false
    }

    return $true
}


function Get-CurrentGraphAccountUpn {
    $context = Get-CurrentGraphContext
    if ($context -and -not [string]::IsNullOrWhiteSpace($context.Account)) {
        return $context.Account
    }
    return $null
}

function Get-DirectoryRoleNamesForPrincipal {
    param([string]$PrincipalPath)

    $roles = @()
    if ([string]::IsNullOrWhiteSpace($PrincipalPath)) { return $roles }

    try {
        $uri = ("v1.0/{0}/memberOf/microsoft.graph.directoryRole?`$select=displayName&`$top=999" -f $PrincipalPath.Trim('/'))
        do {
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($result.value) {
                foreach ($entry in @($result.value)) {
                    if ($entry.displayName) { $roles += [string]$entry.displayName }
                }
            }
            $uri = $result.'@odata.nextLink'
        } while ($uri)
    }
    catch {
        Write-Log "Failed to query directory roles for '$PrincipalPath': $($_.Exception.Message)" "Warning"
    }

    return @($roles | Sort-Object -Unique)
}

function Get-OperatorDirectoryRoles {
    return @(Get-DirectoryRoleNamesForPrincipal -PrincipalPath 'me')
}

function Get-TargetUserDirectoryRoles {
    param([string]$UserId)
    if ([string]::IsNullOrWhiteSpace($UserId)) { return @() }
    return @(Get-DirectoryRoleNamesForPrincipal -PrincipalPath ("users/{0}" -f $UserId))
}

function Test-PasswordResetCapability {
    param([Parameter(Mandatory = $true)]$Rows)

    $issues = New-Object System.Collections.Generic.List[string]
    $operatorRoles = @(Get-OperatorDirectoryRoles)
    $operatorRolesLower = @($operatorRoles | ForEach-Object { $_.ToLowerInvariant() })

    $nonAdminAllowed = @(
        'global administrator',
        'privileged authentication administrator',
        'user administrator',
        'password administrator',
        'helpdesk administrator',
        'authentication administrator'
    )
    $adminAllowed = @(
        'global administrator',
        'privileged authentication administrator'
    )

    if (-not (Has-GraphScope -Scope 'User-PasswordProfile.ReadWrite.All')) {
        $issues.Add("Missing required delegated Graph scope: User-PasswordProfile.ReadWrite.All")
    }

    if ($Config.MailFrom -and ($Config.MailFrom.Trim().ToLowerInvariant() -ne $Config.AuthenticatedGraphAccount.Trim().ToLowerInvariant())) {
        if (-not (Has-GraphScope -Scope 'Mail.Send.Shared')) {
            $issues.Add("Missing required delegated Graph scope for shared/delegated send: Mail.Send.Shared")
        }
    }

    if (-not $operatorRoles -or $operatorRoles.Count -eq 0) {
        $issues.Add("Unable to confirm Microsoft Entra admin role membership for the connected account '$((Get-CurrentGraphAccountUpn))'.")
    }
    elseif (-not (($operatorRolesLower | Where-Object { $nonAdminAllowed -contains $_ }).Count -gt 0)) {
        $issues.Add("Connected account '$((Get-CurrentGraphAccountUpn))' does not have a password-reset capable Entra role. Current roles: $($operatorRoles -join ', ')")
    }

    foreach ($row in @($Rows)) {
        $upn = [string]$row.Cells['UserPrincipalName'].Value
        $userId = [string]$row.Tag
        if ([string]::IsNullOrWhiteSpace($userId)) {
            $issues.Add("Selected row for '$upn' is missing a Graph user id.")
            continue
        }

        $targetRoles = @(Get-TargetUserDirectoryRoles -UserId $userId)
        $targetRolesLower = @($targetRoles | ForEach-Object { $_.ToLowerInvariant() })
        $isAdminTarget = ($targetRolesLower.Count -gt 0)

        if ($isAdminTarget -and -not (($operatorRolesLower | Where-Object { $adminAllowed -contains $_ }).Count -gt 0)) {
            $issues.Add("Target '$upn' holds admin role(s): $($targetRoles -join ', '). Connected operator lacks Global Administrator or Privileged Authentication Administrator.")
        }
    }

    return [PSCustomObject]@{
        Success = ($issues.Count -eq 0)
        Issues = @($issues)
        OperatorRoles = @($operatorRoles)
    }
}

function Send-PasswordInvalidationNotice {
    param(
        [string]$To,
        [string]$DisplayName,
        [string]$Reason
    )

    $safeName = $DisplayName
    if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = $To }
    $encodedReason = [System.Web.HttpUtility]::HtmlEncode($Reason)
    $html = @"
<html>
<body style='font-family:Segoe UI,Arial,sans-serif;font-size:10.5pt;color:#222;'>
<p>Hello $safeName,</p>
<p><strong>Please ignore the previous temporary password email.</strong></p>
<p>That password was <strong>not applied</strong> to your Microsoft 365 account, so it will not work.</p>
<p>No account change has taken effect yet. Please wait for a corrected follow-up from support before attempting sign-in.</p>
<p><strong>Reason:</strong> $encodedReason</p>
<p>If you need help, contact <a href='mailto:$($Config.SupportEmail)'>$($Config.SupportEmail)</a>.</p>
</body>
</html>
"@
    $plain = @"
Hello $safeName,

Please ignore the previous temporary password email.

That password was NOT applied to your Microsoft 365 account, so it will not work.
No account change has taken effect yet. Please wait for a corrected follow-up from support before attempting sign-in.

Reason: $Reason

Support: $($Config.SupportEmail)
"@

    $message = @{ subject = "Ignore Previous Password Email"; body = @{ contentType='HTML'; content=$html }; toRecipients=@(@{ emailAddress=@{ address=$To; name=$safeName } }) }
    if (-not [string]::IsNullOrWhiteSpace($Config.MailFrom)) {
        $message.from = @{ emailAddress = @{ address = $Config.MailFrom } }
    }
    $payload = @{ message = $message; saveToSentItems = $true } | ConvertTo-Json -Depth 10

    $graphResult = Invoke-WithRetry -OperationName ("Graph invalidation notice to {0}" -f $To) -MaxAttempts $Config.GraphRetryCount -ReconnectGraphOnAuthFailure -ScriptBlock {
        Invoke-MgGraphRequest -Method POST -Uri 'v1.0/me/sendMail' -Body $payload -ContentType 'application/json' -ErrorAction Stop | Out-Null
    }
    if ($graphResult.Success) {
        Write-Log "Sent password invalidation notice to $To via Graph." 'Warning'
        return [PSCustomObject]@{ Success=$true; Transport='Graph'; Message='Invalidation notice accepted by Graph.' }
    }

    if ($Config.AllowLegacySmtpFallback) {
        try {
            if (-not $Script:SmtpCredentials) { $null = Get-SmtpCredentials }
            if ($Script:SmtpCredentials) {
                $smtp = New-Object System.Net.Mail.SmtpClient($Config.SmtpServer, $Config.SmtpPort)
                $smtp.EnableSsl = $true
                $smtp.Credentials = $Script:SmtpCredentials
                $mail = New-Object System.Net.Mail.MailMessage
                $mail.From = $Config.MailFrom
                $mail.To.Add($To)
                $mail.Subject = 'Ignore Previous Password Email'
                $mail.Body = $plain
                $smtp.Send($mail)
                Write-Log "Sent password invalidation notice to $To via SMTP fallback." 'Warning'
                return [PSCustomObject]@{ Success=$true; Transport='SMTP'; Message='Invalidation notice sent via SMTP fallback.' }
            }
        }
        catch {
            Write-Log "Invalidation notice SMTP fallback failed for ${To}: $($_.Exception.Message)" 'Warning'
        }
    }

    return [PSCustomObject]@{ Success=$false; Transport='Graph+SMTP'; Message=("Failed to send invalidation notice: {0}" -f $graphResult.ErrorMessage) }
}

function Connect-Graph {
    try {
        Update-Status "Connecting to Microsoft Graph..."
        Write-Log "Initializing Microsoft Graph connection..." "Info"

        if (-not (Ensure-Module -Name "Microsoft.Graph")) {
            throw "Microsoft.Graph module is not available."
        }

        $requiredScopes = Get-GraphRequiredScopes
        Write-Log "Required scopes: $($requiredScopes -join ', ')" "Info"

        $context = Get-CurrentGraphContext
        if ($context -and $context.Account) {
            Write-Log "Existing Graph context detected for: $($context.Account)" "Info"

            if ((Test-GraphScopes -Scopes $requiredScopes) -and (Validate-GraphAccount)) {
                $Script:GraphConnected = $true
                return $true
            }

            Write-Log "Existing Graph context is missing scopes or using the wrong account. Reconnecting..." "Warning"
            Disconnect-Graph
        }

        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
        Start-Sleep -Milliseconds 400

        $context = Get-CurrentGraphContext
        if (-not $context -or -not $context.Account) {
            throw "Connection completed but no account context was returned."
        }

        if (-not (Test-GraphScopes -Scopes $requiredScopes)) {
            throw "Graph connection succeeded but one or more required scopes were not granted."
        }

        if (-not (Validate-GraphAccount)) {
            throw "Graph connection uses an unexpected account."
        }

        Write-Log "Connected successfully as: $($context.Account)" "Success"
        Write-Log "Tenant ID: $($context.TenantId)" "Info"
        Write-Log "Scopes granted: $($context.Scopes -join ', ')" "Info"

        if (-not (Has-GraphScope -Scope "AuditLog.Read.All")) {
            Write-Log "AuditLog.Read.All is not granted; Last Sign-In will degrade gracefully." "Warning"
        }

        $Script:GraphConnected = $true
        return $true
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "Error"
        $Script:GraphConnected = $false

        [System.Windows.Forms.MessageBox]::Show(
            "Failed to connect to Microsoft Graph.`n`nError: $($_.Exception.Message)`n`nPlease ensure:`n• Microsoft.Graph is installed`n• Required scopes were consented`n• You sign in with the intended admin account",
            "Graph Connection Failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )

        return $false
    }
}

function Connect-Exchange {
    try {
        Update-Status "Connecting to Exchange Online..."
        Write-Log "Initializing Exchange Online connection..." "Info"

        if (-not (Ensure-Module -Name "ExchangeOnlineManagement")) {
            throw "ExchangeOnlineManagement module is not available."
        }

        $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingConnection) {
            Write-Log "Already connected to Exchange Online" "Info"
            $Script:ExchangeConnected = $true
            return $true
        }

        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop | Out-Null
        Start-Sleep -Milliseconds 400

        $testConnection = Get-OrganizationConfig -ErrorAction Stop
        if (-not $testConnection) {
            throw "Exchange Online connection could not be verified."
        }

        Write-Log "Connected successfully to Exchange Online" "Success"
        Write-Log "Organization: $($testConnection.Name)" "Info"
        $Script:ExchangeConnected = $true
        return $true
    }
    catch {
        Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" "Warning"
        $Script:ExchangeConnected = $false
        return $false
    }
}

function Disconnect-Exchange {
    try {
        if ($Script:ExchangeConnected) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Disconnected from Exchange Online" "Info"
            $Script:ExchangeConnected = $false
        }
    }
    catch {
        Write-Log "Error during Exchange disconnect: $($_.Exception.Message)" "Warning"
    }
}

function Enable-SMTPAuth {
    param([string]$Mailbox)

    try {
        if ([string]::IsNullOrWhiteSpace($Mailbox)) {
            return $false
        }

        if (-not $Script:ExchangeConnected) {
            if (-not (Connect-Exchange)) {
                return $false
            }
        }

        Write-Log "Checking SMTP auth status for mailbox: $Mailbox" "Info"
        $mailboxConfig = Get-CASMailbox -Identity $Mailbox -ErrorAction Stop

        if ($mailboxConfig.SmtpClientAuthenticationDisabled -eq $true) {
            Write-Log "SMTP AUTH is disabled for $Mailbox. Attempting to enable..." "Warning"
            Set-CASMailbox -Identity $Mailbox -SmtpClientAuthenticationDisabled $false -ErrorAction Stop
            Write-Log "SMTP AUTH enabled for $Mailbox. Waiting 15 seconds for propagation..." "Success"
            Wait-WithUi -Seconds 15 -Prefix "Waiting for SMTP AUTH propagation"
        }
        else {
            Write-Log "SMTP AUTH already enabled for $Mailbox" "Info"
        }

        return $true
    }
    catch {
        Write-Log "Failed to enable SMTP AUTH for ${Mailbox}: $($_.Exception.Message)" "Warning"
        return $false
    }
}

function Get-SmtpCredentials {
    if ($null -eq $Script:SmtpCredentials) {
        Write-Log "Prompting for SMTP fallback credentials for $($Config.SmtpAuthUser)..." "Warning"
        $Script:SmtpCredentials = Get-Credential -UserName $Config.SmtpAuthUser -Message "Enter the password for SMTP fallback account '$($Config.SmtpAuthUser)'.`n`nThis is used only if Graph sendMail fails and SMTP fallback is still allowed in your tenant."
    }

    return $Script:SmtpCredentials
}

function Get-ErrorClassification {
    param([string]$Message)

    $m = (Get-ConditionalText -Condition ([bool]$Message) -TrueText $Message.ToLowerInvariant() -FalseText "")

    if ($m -match "sendasdenied|does not have the right to send mail|send on behalf|send as") { return "SendAsDenied" }
    if ($m -match "mail.send.shared") { return "MissingSharedScope" }
    if ($m -match "password.*policy|password does not satisfy|does not comply|banned password|passwordprofile|password validation") { return "PasswordPolicy" }
    if ($m -match "429|too many requests|throttl|temporar|timeout|timed out|service unavailable|connection.*closed|socket|503|504|gateway") { return "Transient" }
    if ($m -match "401|403|authentication|authorization|insufficient privileges|access token|consent|forbidden|unauthorized") { return "Auth" }
    if ($m -match "not found|resource .* does not exist|cannot find") { return "NotFound" }
    if ($m -match "recipient|mailbox unavailable|not a valid email|invalid address") { return "Recipient" }
    return "Other"
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][string]$OperationName,
        [int]$MaxAttempts = 3,
        [switch]$ReconnectGraphOnAuthFailure
    )

    $lastErrorMessage = $null
    $lastClassification = "Other"

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = & $ScriptBlock
            return [PSCustomObject]@{
                Success        = $true
                Result         = $result
                Attempt        = $attempt
                ErrorMessage   = $null
                Classification = $null
            }
        }
        catch {
            $lastErrorMessage = $_.Exception.Message
            $lastClassification = Get-ErrorClassification -Message $lastErrorMessage

            if ($attempt -lt $MaxAttempts) {
                Write-Log "$OperationName failed (attempt $attempt/$MaxAttempts): $lastErrorMessage" "Warning"
            }
            else {
                Write-Log "$OperationName failed (attempt $attempt/$MaxAttempts): $lastErrorMessage" "Error"
            }

            $shouldRetry = $false

            if ($attempt -lt $MaxAttempts) {
                switch ($lastClassification) {
                    "Transient" { $shouldRetry = $true }
                    "Auth" {
                        if ($ReconnectGraphOnAuthFailure) {
                            Write-Log "Attempting Graph reconnect before retrying $OperationName..." "Warning"
                            $shouldRetry = Connect-Graph
                        }
                    }
                    default { $shouldRetry = $false }
                }
            }

            if (-not $shouldRetry) {
                break
            }

            $delay = [Math]::Min(8, [int][Math]::Pow(2, $attempt))
            Wait-WithUi -Seconds $delay -Prefix "Retrying $OperationName in"
        }
    }

    return [PSCustomObject]@{
        Success        = $false
        Result         = $null
        Attempt        = $MaxAttempts
        ErrorMessage   = $lastErrorMessage
        Classification = $lastClassification
    }
}

function Get-RandomChar {
    param([string]$Characters)

    return $Characters[(Get-Random -Minimum 0 -Maximum $Characters.Length)]
}

function Generate-Password {
    $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower = "abcdefghijkmnopqrstuvwxyz"
    $digits = "23456789"
    $symbols = "!@#$%&*+-_=?"
    $all = $upper + $lower + $digits + $symbols

    $chars = @(
        (Get-RandomChar -Characters $upper),
        (Get-RandomChar -Characters $lower),
        (Get-RandomChar -Characters $digits),
        (Get-RandomChar -Characters $symbols)
    )

    for ($i = 0; $i -lt 12; $i++) {
        $chars += (Get-RandomChar -Characters $all)
    }

    $shuffled = $chars | Sort-Object { Get-Random }
    return -join $shuffled
}

function New-CredentialEmailContent {
    param(
        [string]$To,
        [string]$DisplayName,
        [string]$Password,
        [datetime]$ActivationTime,
        [bool]$IsCorrection = $false
    )

    $safeName = [System.Web.HttpUtility]::HtmlEncode($DisplayName)
    $safeTo = [System.Web.HttpUtility]::HtmlEncode($To)
    $safePassword = [System.Web.HttpUtility]::HtmlEncode($Password)
    $safeSupportEmail = [System.Web.HttpUtility]::HtmlEncode($Config.SupportEmail)
    $safeSupportPhone = [System.Web.HttpUtility]::HtmlEncode($Config.SupportPhone)
    $activationLocal = $ActivationTime.ToString("yyyy-MM-dd hh:mm:ss tt")

    if ($IsCorrection) {
        $subject = "CORRECTION: Updated temporary Microsoft 365 password"
        $headline = "🔁 Updated temporary password"
        $intro = "A previous temporary-password message was superseded. Use only the password shown in this message."
        $bannerColor = "#b54708"
    }
    else {
        $subject = "ACTION REQUIRED: Your temporary Microsoft 365 password will activate shortly"
        $headline = "🔐 Temporary Microsoft 365 password prepared"
        $intro = "A temporary password has been generated for your Microsoft 365 account. For safety, it is being emailed before it is applied."
        $bannerColor = "#0078d4"
    }

    $body = @"
<html>
<body style="font-family: Calibri, Segoe UI, sans-serif; line-height: 1.5; color: #222;">
<h2 style="color: $bannerColor;">$headline</h2>
<p>Hi <strong>$safeName</strong>,</p>
<p>$intro</p>
<div style="background: #f3f2f1; padding: 15px; border-left: 4px solid $bannerColor; margin: 20px 0;">
  <strong>📋 LOGIN DETAILS</strong><br><br>
  <strong>Username:</strong> $safeTo<br>
  <strong>Temporary Password:</strong> <span style="font-family: Consolas, monospace; background: #fff; padding: 2px 6px; font-size: 14px;">$safePassword</span><br>
  <strong>Password activation time:</strong> approximately <strong>$activationLocal</strong><br>
  <em>⚠️ This password is not active until the activation time above.</em>
</div>
<h3>🚀 Next steps</h3>
<ol>
  <li>Wait until the activation time shown above.</li>
  <li>Go to <a href="https://portal.office.com">https://portal.office.com</a>.</li>
  <li>Sign in with your username and temporary password.</li>
  <li>You will be prompted to create a new password.</li>
  <li>Complete any required MFA steps.</li>
</ol>
<h3>💡 Tips</h3>
<ul>
  <li>Use an <strong>InPrivate / Incognito</strong> window for the first sign-in.</li>
  <li>If login does not work on the first attempt, wait another 1–2 minutes and try again.</li>
  <li>Delete this message after you successfully sign in and change your password.</li>
</ul>
<h3>🆘 Need help?</h3>
<p>Reply to this email or contact IT support:<br>
📧 $safeSupportEmail<br>
📞 $safeSupportPhone</p>
<hr>
<p style="font-size: 12px; color: #666;">
  Security notice: this email contains a temporary credential and should be stored only as long as necessary.
</p>
</body>
</html>
"@

    return [PSCustomObject]@{
        Subject = $subject
        Body    = $body
    }
}

function Send-GraphCredentialEmail {
    param(
        [string]$To,
        [string]$DisplayName,
        [string]$Password,
        [datetime]$ActivationTime,
        [bool]$IsCorrection = $false
    )

    if (-not (Connect-Graph)) {
        return [PSCustomObject]@{
            Success        = $false
            Transport      = "Graph"
            Message        = "Graph connection is unavailable."
            Classification = "Auth"
        }
    }

    $content = New-CredentialEmailContent -To $To -DisplayName $DisplayName -Password $Password -ActivationTime $ActivationTime -IsCorrection $IsCorrection

    $message = @{
        subject = $content.Subject
        body = @{
            contentType = "HTML"
            content = $content.Body
        }
        toRecipients = @(
            @{
                emailAddress = @{
                    address = $To
                    name    = $DisplayName
                }
            }
        )
    }

    if (-not [string]::IsNullOrWhiteSpace($Config.MailFrom)) {
        $message.from = @{
            emailAddress = @{
                address = $Config.MailFrom
            }
        }
    }

    $payload = @{
        message = $message
        saveToSentItems = $true
    } | ConvertTo-Json -Depth 10

    $operationName = "Graph sendMail to $To"
    $result = Invoke-WithRetry -OperationName $operationName -MaxAttempts $Config.GraphRetryCount -ReconnectGraphOnAuthFailure -ScriptBlock {
        Invoke-MgGraphRequest -Method POST -Uri "v1.0/me/sendMail" -Body $payload -ContentType "application/json" -ErrorAction Stop | Out-Null
    }

    if ($result.Success) {
        Write-Log "Graph accepted credential email for $To." "Success"
        return [PSCustomObject]@{
            Success        = $true
            Transport      = "Graph"
            Message        = "Graph accepted the message request (202 Accepted semantics)."
            Classification = $null
        }
    }

    return [PSCustomObject]@{
        Success        = $false
        Transport      = "Graph"
        Message        = $result.ErrorMessage
        Classification = $result.Classification
    }
}

function Send-SmtpCredentialEmail {
    param(
        [string]$To,
        [string]$DisplayName,
        [string]$Password,
        [datetime]$ActivationTime,
        [bool]$IsCorrection = $false
    )

    if (-not $Config.AllowLegacySmtpFallback) {
        return [PSCustomObject]@{
            Success        = $false
            Transport      = "SMTP"
            Message        = "Legacy SMTP fallback is disabled by configuration."
            Classification = "Other"
        }
    }

    Write-Log "Attempting legacy SMTP fallback for $To. This path may fail in tenants where Basic SMTP AUTH is no longer usable." "Warning"

    try {
        if ($Config.TryEnableSmtpAuthOnFallback) {
            $null = Enable-SMTPAuth -Mailbox $Config.SmtpAuthUser
        }

        $smtpCreds = Get-SmtpCredentials
        if ($null -eq $smtpCreds) {
            throw "No SMTP credentials were supplied."
        }

        $content = New-CredentialEmailContent -To $To -DisplayName $DisplayName -Password $Password -ActivationTime $ActivationTime -IsCorrection $IsCorrection

        $mailMessage = New-Object System.Net.Mail.MailMessage
        $mailMessage.From = New-Object System.Net.Mail.MailAddress($Config.MailFrom)
        $mailMessage.To.Add($To)
        $mailMessage.Subject = $content.Subject
        $mailMessage.Body = $content.Body
        $mailMessage.IsBodyHtml = $true

        $smtpClient = New-Object System.Net.Mail.SmtpClient
        $smtpClient.Host = $Config.SmtpServer
        $smtpClient.Port = $Config.SmtpPort
        $smtpClient.EnableSsl = $true
        $smtpClient.UseDefaultCredentials = $false
        $smtpClient.Credentials = $smtpCreds
        $smtpClient.Timeout = 30000

        $smtpClient.Send($mailMessage)

        $mailMessage.Dispose()
        $smtpClient.Dispose()

        Write-Log "SMTP fallback sent credential email to $To." "Success"
        return [PSCustomObject]@{
            Success        = $true
            Transport      = "SMTP"
            Message        = "SMTP fallback completed successfully."
            Classification = $null
        }
    }
    catch {
        try { if ($mailMessage) { $mailMessage.Dispose() } } catch {}
        try { if ($smtpClient) { $smtpClient.Dispose() } } catch {}

        return [PSCustomObject]@{
            Success        = $false
            Transport      = "SMTP"
            Message        = $_.Exception.Message
            Classification = (Get-ErrorClassification -Message $_.Exception.Message)
        }
    }
}

function Send-CredentialEmail {
    param(
        [string]$To,
        [string]$DisplayName,
        [string]$Password,
        [datetime]$ActivationTime,
        [bool]$IsCorrection = $false
    )

    $graphResult = Send-GraphCredentialEmail -To $To -DisplayName $DisplayName -Password $Password -ActivationTime $ActivationTime -IsCorrection $IsCorrection
    if ($graphResult.Success) {
        return $graphResult
    }

    Write-Log "Graph mail path failed for ${To}: $($graphResult.Message)" "Warning"

    $smtpResult = Send-SmtpCredentialEmail -To $To -DisplayName $DisplayName -Password $Password -ActivationTime $ActivationTime -IsCorrection $IsCorrection
    if ($smtpResult.Success) {
        return $smtpResult
    }

    return [PSCustomObject]@{
        Success        = $false
        Transport      = "Graph+SMTP"
        Message        = "Graph failure: $($graphResult.Message) | SMTP failure: $($smtpResult.Message)"
        Classification = (Get-ConditionalText -Condition ([bool]$smtpResult.Classification) -TrueText $smtpResult.Classification -FalseText $graphResult.Classification)
    }
}

function Apply-Password {
    param(
        [string]$UserId,
        [string]$Password
    )

    $passwordProfile = @{
        Password = $Password
        ForceChangePasswordNextSignIn = $true
        ForceChangePasswordNextSignInWithMfa = $false
    }

    $operationName = "Apply password for user $UserId"
    $result = Invoke-WithRetry -OperationName $operationName -MaxAttempts $Config.PasswordApplyRetryCount -ReconnectGraphOnAuthFailure -ScriptBlock {
        Update-MgUser -UserId $UserId -PasswordProfile $passwordProfile -ErrorAction Stop
    }

    if ($result.Success) {
        Write-Log "Password applied successfully for: $UserId" "Success"
        return [PSCustomObject]@{
            Success        = $true
            Message        = "Password applied successfully."
            Classification = $null
        }
    }

    return [PSCustomObject]@{
        Success        = $false
        Message        = $result.ErrorMessage
        Classification = $result.Classification
    }
}

function Get-UserSignInActivityMap {
    $map = @{}

    if (-not (Has-GraphScope -Scope "AuditLog.Read.All")) {
        return $map
    }

    try {
        Write-Log "AuditLog.Read.All detected. Attempting to load sign-in activity..." "Info"
        $uri = "v1.0/users?`$select=id,signInActivity&`$top=500"

        do {
            $pageResult = Invoke-WithRetry -OperationName "Load sign-in activity" -MaxAttempts 2 -ReconnectGraphOnAuthFailure -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            }

            if (-not $pageResult.Success) {
                throw $pageResult.ErrorMessage
            }

            $page = $pageResult.Result
            foreach ($entry in @($page.value)) {
                $lastSeen = $null

                if ($entry.signInActivity.lastSuccessfulSignInDateTime) {
                    $lastSeen = $entry.signInActivity.lastSuccessfulSignInDateTime
                }
                elseif ($entry.signInActivity.lastSignInDateTime) {
                    $lastSeen = $entry.signInActivity.lastSignInDateTime
                }

                if ($entry.id) {
                    if ($lastSeen) {
                        try {
                            $map[$entry.id] = (Get-Date $lastSeen).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                        }
                        catch {
                            $map[$entry.id] = "$lastSeen"
                        }
                    }
                    else {
                        $map[$entry.id] = "No data"
                    }
                }
            }

            $uri = $page.'@odata.nextLink'
            if ($uri -and $uri -like 'https://graph.microsoft.com/*') {
                $uri = $uri -replace '^https://graph.microsoft.com/', ''
            }
        }
        while ($uri)
    }
    catch {
        Write-Log "Unable to retrieve sign-in activity. Continuing without it: $($_.Exception.Message)" "Warning"
    }

    return $map
}

function Process-UserReset {
    param([Parameter(Mandatory = $true)]$Row)

    $upn = [string]$Row.Cells["UserPrincipalName"].Value
    $displayName = [string]$Row.Cells["DisplayName"].Value
    $userId = [string]$Row.Tag

    if (-not (Test-ValidEmailAddress -Address $upn)) {
        Set-RowStatus -Row $Row -Status "Invalid Email" -Color ([System.Drawing.Color]::LightCoral)
        return [PSCustomObject]@{
            User        = $upn
            DisplayName = $displayName
            Status      = "Invalid Email"
            Password    = ""
            Transport   = ""
            Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Notes       = "UPN is blank or invalid."
        }
    }

    if ([string]::IsNullOrWhiteSpace($userId)) {
        Set-RowStatus -Row $Row -Status "Missing User ID" -Color ([System.Drawing.Color]::LightCoral)
        return [PSCustomObject]@{
            User        = $upn
            DisplayName = $displayName
            Status      = "Missing User ID"
            Password    = ""
            Transport   = ""
            Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Notes       = "The selected row does not contain a Graph user id."
        }
    }

    $record = [PSCustomObject]@{
        User        = $upn
        DisplayName = $displayName
        Password    = ""
        Status      = "Pending"
        Transport   = ""
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Notes       = ""
    }

    $Script:PasswordRecords += $record

    for ($regenAttempt = 0; $regenAttempt -le $Config.PasswordRegenerationAttempts; $regenAttempt++) {
        $tempPassword = Generate-Password
        $activationTime = (Get-Date).AddSeconds($Config.PropagationWaitSeconds)
        $isCorrection = ($regenAttempt -gt 0)

        if ($isCorrection) {
            Write-Log "Generating replacement password for $upn after policy rejection / recovery flow." "Warning"
        }

        Set-RowStatus -Row $Row -Status (Get-ConditionalText -Condition $isCorrection -TrueText "Correction Email Pending" -FalseText "Email Pending") -Color ([System.Drawing.Color]::LightGoldenrodYellow)
        Update-Status "Preparing credential message for $upn"

        $sendResult = Send-CredentialEmail -To $upn -DisplayName $displayName -Password $tempPassword -ActivationTime $activationTime -IsCorrection $isCorrection

        if (-not $sendResult.Success) {
            $record.Password = ""
            $record.Status = "Email Failed"
            $record.Transport = $sendResult.Transport
            $record.Notes = $sendResult.Message
            Set-RowStatus -Row $Row -Status "Email Failed" -Color ([System.Drawing.Color]::LightCoral)

            return [PSCustomObject]@{
                User        = $upn
                DisplayName = $displayName
                Status      = "Email Failed"
                Password    = ""
                Transport   = $sendResult.Transport
                Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Notes       = $sendResult.Message
            }
        }

        $record.Password = $tempPassword
        $record.Status = (Get-ConditionalText -Condition $isCorrection -TrueText "Correction Mail Accepted" -FalseText "Mail Accepted")
        $record.Transport = $sendResult.Transport
        $record.Notes = $sendResult.Message

        Set-RowStatus -Row $Row -Status "Mail Accepted - Waiting" -Color ([System.Drawing.Color]::LightYellow)
        Wait-WithUi -Seconds $Config.PropagationWaitSeconds -Prefix "Waiting before password activation"

        Set-RowStatus -Row $Row -Status "Applying Password" -Color ([System.Drawing.Color]::LightSkyBlue)
        $applyResult = Apply-Password -UserId $userId -Password $tempPassword

        if ($applyResult.Success) {
            $record.Status = (Get-ConditionalText -Condition $isCorrection -TrueText "Complete (Corrected)" -FalseText "Complete")
            $record.Notes = "Mail accepted via $($sendResult.Transport); password applied after wait window."
            Set-RowStatus -Row $Row -Status "Complete ✓" -Color ([System.Drawing.Color]::LightGreen)

            return [PSCustomObject]@{
                User        = $upn
                DisplayName = $displayName
                Status      = "Success"
                Password    = (Mask-Password -Password $tempPassword)
                Transport   = $sendResult.Transport
                Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Notes       = $record.Notes
            }
        }

        Write-Log "Password application failed for ${upn}: $($applyResult.Message)" "Warning"

        if (($applyResult.Classification -eq "PasswordPolicy") -and ($regenAttempt -lt $Config.PasswordRegenerationAttempts)) {
            $record.Status = "Policy Rejected - Resending"
            $record.Notes = "Password policy rejected an emailed candidate; issuing corrected credential email."
            Set-RowStatus -Row $Row -Status "Policy Rejected - Resending" -Color ([System.Drawing.Color]::Khaki)
            continue
        }

        $notice = Send-PasswordInvalidationNotice -To $upn -DisplayName $displayName -Reason $applyResult.Message
        if ($notice.Success) {
            $record.Status = "Manual Follow-Up Required"
            $record.Notes = "Mail was accepted, but password was not applied. Invalidation notice sent via $($notice.Transport). Error: $($applyResult.Message)"
            Set-RowStatus -Row $Row -Status "Password Not Applied / Notice Sent" -Color ([System.Drawing.Color]::Orange)
        }
        else {
            $record.Status = "Critical Follow-Up Required"
            $record.Notes = "Mail was accepted, but password was not applied. Invalidation notice also failed. Apply error: $($applyResult.Message) | Notice error: $($notice.Message)"
            Set-RowStatus -Row $Row -Status "CRITICAL - Notice Failed" -Color ([System.Drawing.Color]::OrangeRed)
        }

        return [PSCustomObject]@{
            User        = $upn
            DisplayName = $displayName
            Status      = "Password Apply Failed"
            Password    = (Mask-Password -Password $tempPassword)
            Transport   = "$($sendResult.Transport) / $($notice.Transport)"
            Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Notes       = $record.Notes
        }
    }

    $record.Status = "Unexpected Failure"
    $record.Notes = "Password regeneration loop exhausted unexpectedly."
    Set-RowStatus -Row $Row -Status "Unexpected Failure" -Color ([System.Drawing.Color]::OrangeRed)

    return [PSCustomObject]@{
        User        = $upn
        DisplayName = $displayName
        Status      = "Unexpected Failure"
        Password    = ""
        Transport   = ""
        Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Notes       = "Password regeneration loop exhausted unexpectedly."
    }
}

# ====================== FORM SETUP ======================
$Script:Form = New-Object System.Windows.Forms.Form
$Script:Form.Text = "O365 Batch User Password Tool - $($Config.Domain)"
$Script:Form.Size = New-Object System.Drawing.Size(1260, 780)
$Script:Form.StartPosition = "CenterScreen"
$Script:Form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Script:Form.BackColor = [System.Drawing.Color]::White
$Script:Form.MinimumSize = New-Object System.Drawing.Size(1060, 680)

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Size = New-Object System.Drawing.Size(1220, 86)
$headerPanel.Location = New-Object System.Drawing.Point(20, 10)
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$headerPanel.Dock = [System.Windows.Forms.DockStyle]::Top

$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = "🔐 O365 Batch User Password Tool"
$headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$headerLabel.ForeColor = [System.Drawing.Color]::White
$headerLabel.AutoSize = $true
$headerLabel.Location = New-Object System.Drawing.Point(20, 18)

$headerSubLabel = New-Object System.Windows.Forms.Label
$headerSubLabel.Text = "Flow: generate password → email user → wait $($Config.PropagationWaitSeconds)s → apply password → force password change"
$headerSubLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$headerSubLabel.ForeColor = [System.Drawing.Color]::White
$headerSubLabel.AutoSize = $true
$headerSubLabel.Location = New-Object System.Drawing.Point(20, 52)

$headerPanel.Controls.Add($headerLabel)
$headerPanel.Controls.Add($headerSubLabel)
$Script:Form.Controls.Add($headerPanel)

$statusPanel = New-Object System.Windows.Forms.Panel
$statusPanel.Size = New-Object System.Drawing.Size(1220, 42)
$statusPanel.Location = New-Object System.Drawing.Point(20, 102)
$statusPanel.BackColor = [System.Drawing.Color]::FromArgb(243, 242, 241)
$statusPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$statusPanel.Dock = [System.Windows.Forms.DockStyle]::Top

$Script:StatusLabel = New-Object System.Windows.Forms.Label
$Script:StatusLabel.Text = "📡 Status: Initializing..."
$Script:StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Script:StatusLabel.AutoSize = $true
$Script:StatusLabel.Location = New-Object System.Drawing.Point(15, 10)

$statusPanel.Controls.Add($Script:StatusLabel)
$Script:Form.Controls.Add($statusPanel)

function Get-ClampedIntValue {
    param(
        [object]$Value,
        [int]$DefaultValue,
        [int]$Minimum,
        [int]$Maximum
    )

    $parsed = $DefaultValue
    try {
        if ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value)) {
            $parsed = [int]$Value
        }
    }
    catch {
        $parsed = $DefaultValue
    }

    if ($parsed -lt $Minimum) { return $Minimum }
    if ($parsed -gt $Maximum) { return $Maximum }
    return $parsed
}

$Config.PropagationWaitSeconds = Get-ClampedIntValue -Value $Config.PropagationWaitSeconds -DefaultValue 20 -Minimum 0 -Maximum 600
$Config.GraphRetryDelaySeconds = Get-ClampedIntValue -Value $Config.GraphRetryDelaySeconds -DefaultValue 2 -Minimum 1 -Maximum 60
$Config.SmtpAuthPropagationWaitSeconds = Get-ClampedIntValue -Value $Config.SmtpAuthPropagationWaitSeconds -DefaultValue 15 -Minimum 0 -Maximum 300

$configPanel = New-Object System.Windows.Forms.Panel
$configPanel.Size = New-Object System.Drawing.Size(1220, 118)
$configPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$configPanel.BackColor = [System.Drawing.Color]::White
$configPanel.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)

$sendAsLabel = New-Object System.Windows.Forms.Label
$sendAsLabel.Text = "Send As address:"
$sendAsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$sendAsLabel.AutoSize = $true
$sendAsLabel.Location = New-Object System.Drawing.Point(15, 13)

$Script:MailFromTextBox = New-Object System.Windows.Forms.TextBox
$Script:MailFromTextBox.Text = $Config.MailFrom
$Script:MailFromTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Script:MailFromTextBox.Size = New-Object System.Drawing.Size(330, 28)
$Script:MailFromTextBox.Location = New-Object System.Drawing.Point(135, 10)

$senderHintLabel = New-Object System.Windows.Forms.Label
$senderHintLabel.Text = "Used for Graph delegated send and SMTP fallback display-from."
$senderHintLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$senderHintLabel.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
$senderHintLabel.AutoSize = $true
$senderHintLabel.Location = New-Object System.Drawing.Point(480, 13)

$expectedGraphLabel = New-Object System.Windows.Forms.Label
$expectedGraphLabel.Text = "Expected Graph login:"
$expectedGraphLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$expectedGraphLabel.AutoSize = $true
$expectedGraphLabel.Location = New-Object System.Drawing.Point(15, 50)

$Script:AuthenticatedGraphAccountTextBox = New-Object System.Windows.Forms.TextBox
$Script:AuthenticatedGraphAccountTextBox.Text = $Config.AuthenticatedGraphAccount
$Script:AuthenticatedGraphAccountTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Script:AuthenticatedGraphAccountTextBox.Size = New-Object System.Drawing.Size(330, 28)
$Script:AuthenticatedGraphAccountTextBox.Location = New-Object System.Drawing.Point(135, 47)

$expectedGraphHintLabel = New-Object System.Windows.Forms.Label
$expectedGraphHintLabel.Text = "Used for Graph-account mismatch checks and SMTP fallback auth default."
$expectedGraphHintLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$expectedGraphHintLabel.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
$expectedGraphHintLabel.AutoSize = $true
$expectedGraphHintLabel.Location = New-Object System.Drawing.Point(480, 50)

$activationDelayLabel = New-Object System.Windows.Forms.Label
$activationDelayLabel.Text = "Apply delay (sec):"
$activationDelayLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$activationDelayLabel.AutoSize = $true
$activationDelayLabel.Location = New-Object System.Drawing.Point(15, 82)

$Script:ActivationDelayUpDown = New-Object System.Windows.Forms.NumericUpDown
$Script:ActivationDelayUpDown.Minimum = 0
$Script:ActivationDelayUpDown.Maximum = 600
$Script:ActivationDelayUpDown.Value = [decimal]$Config.PropagationWaitSeconds
$Script:ActivationDelayUpDown.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Script:ActivationDelayUpDown.Size = New-Object System.Drawing.Size(70, 28)
$Script:ActivationDelayUpDown.Location = New-Object System.Drawing.Point(135, 79)

$retryDelayLabel = New-Object System.Windows.Forms.Label
$retryDelayLabel.Text = "Retry delay (sec):"
$retryDelayLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$retryDelayLabel.AutoSize = $true
$retryDelayLabel.Location = New-Object System.Drawing.Point(225, 82)

$Script:RetryDelayUpDown = New-Object System.Windows.Forms.NumericUpDown
$Script:RetryDelayUpDown.Minimum = 1
$Script:RetryDelayUpDown.Maximum = 60
$Script:RetryDelayUpDown.Value = [decimal]$Config.GraphRetryDelaySeconds
$Script:RetryDelayUpDown.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Script:RetryDelayUpDown.Size = New-Object System.Drawing.Size(70, 28)
$Script:RetryDelayUpDown.Location = New-Object System.Drawing.Point(342, 79)

$smtpWaitLabel = New-Object System.Windows.Forms.Label
$smtpWaitLabel.Text = "SMTP wait (sec):"
$smtpWaitLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$smtpWaitLabel.AutoSize = $true
$smtpWaitLabel.Location = New-Object System.Drawing.Point(432, 82)

$Script:SmtpWaitUpDown = New-Object System.Windows.Forms.NumericUpDown
$Script:SmtpWaitUpDown.Minimum = 0
$Script:SmtpWaitUpDown.Maximum = 300
$Script:SmtpWaitUpDown.Value = [decimal]$Config.SmtpAuthPropagationWaitSeconds
$Script:SmtpWaitUpDown.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Script:SmtpWaitUpDown.Size = New-Object System.Drawing.Size(70, 28)
$Script:SmtpWaitUpDown.Location = New-Object System.Drawing.Point(541, 79)

$timerHintLabel = New-Object System.Windows.Forms.Label
$timerHintLabel.Text = "Applies to activation wait, retry pacing, and SMTP fallback propagation wait."
$timerHintLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$timerHintLabel.ForeColor = [System.Drawing.Color]::FromArgb(96, 94, 92)
$timerHintLabel.AutoSize = $true
$timerHintLabel.Location = New-Object System.Drawing.Point(630, 82)

$configPanel.Controls.Add($sendAsLabel)
$configPanel.Controls.Add($Script:MailFromTextBox)
$configPanel.Controls.Add($senderHintLabel)
$configPanel.Controls.Add($expectedGraphLabel)
$configPanel.Controls.Add($Script:AuthenticatedGraphAccountTextBox)
$configPanel.Controls.Add($expectedGraphHintLabel)
$configPanel.Controls.Add($activationDelayLabel)
$configPanel.Controls.Add($Script:ActivationDelayUpDown)
$configPanel.Controls.Add($retryDelayLabel)
$configPanel.Controls.Add($Script:RetryDelayUpDown)
$configPanel.Controls.Add($smtpWaitLabel)
$configPanel.Controls.Add($Script:SmtpWaitUpDown)
$configPanel.Controls.Add($timerHintLabel)
$Script:Form.Controls.Add($configPanel)

$Script:DataGridView = New-Object System.Windows.Forms.DataGridView
$Script:DataGridView.Size = New-Object System.Drawing.Size(1220, 360)
$Script:DataGridView.Dock = [System.Windows.Forms.DockStyle]::Fill
$Script:DataGridView.AllowUserToAddRows = $false
$Script:DataGridView.AllowUserToDeleteRows = $false
$Script:DataGridView.ReadOnly = $false
$Script:DataGridView.MultiSelect = $false
$Script:DataGridView.SelectionMode = "FullRowSelect"
$Script:DataGridView.BackgroundColor = [System.Drawing.Color]::White
$Script:DataGridView.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$Script:DataGridView.RowHeadersWidth = 40
$Script:DataGridView.RowHeadersDefaultCellStyle.Alignment = "MiddleCenter"
$Script:DataGridView.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$Script:DataGridView.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(243, 242, 241)
$Script:DataGridView.EnableHeadersVisualStyles = $false
$Script:DataGridView.ColumnHeadersHeight = 35
$Script:DataGridView.RowTemplate.Height = 35
$Script:DataGridView.AutoSizeColumnsMode = "Fill"

$checkboxCol = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$checkboxCol.HeaderText = ""
$checkboxCol.Width = 40
$checkboxCol.Name = "Select"

$nameCol = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$nameCol.HeaderText = "Display Name"
$nameCol.Name = "DisplayName"

$emailCol = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$emailCol.HeaderText = "Email Address"
$emailCol.Name = "UserPrincipalName"

$statusCol = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$statusCol.HeaderText = "Status"
$statusCol.Name = "Status"

$lastLoginCol = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$lastLoginCol.HeaderText = "Last Sign-In"
$lastLoginCol.Name = "LastSignIn"

$Script:DataGridView.Columns.AddRange($checkboxCol, $nameCol, $emailCol, $statusCol, $lastLoginCol)
$Script:Form.Controls.Add($Script:DataGridView)

$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Size = New-Object System.Drawing.Size(1220, 62)
$buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom

$loadBtn = New-Object System.Windows.Forms.Button
$loadBtn.Text = "📥 Load Users"
$loadBtn.Size = New-Object System.Drawing.Size(130, 40)
$loadBtn.Location = New-Object System.Drawing.Point(0, 10)
$loadBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$loadBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$loadBtn.ForeColor = [System.Drawing.Color]::White
$loadBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat

$sendBtn = New-Object System.Windows.Forms.Button
$sendBtn.Text = "📧 Run Workflow"
$sendBtn.Size = New-Object System.Drawing.Size(150, 40)
$sendBtn.Location = New-Object System.Drawing.Point(140, 10)
$sendBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$sendBtn.BackColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
$sendBtn.ForeColor = [System.Drawing.Color]::White
$sendBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$sendBtn.Enabled = $false

$viewPwBtn = New-Object System.Windows.Forms.Button
$viewPwBtn.Text = "🔑 View Passwords"
$viewPwBtn.Size = New-Object System.Drawing.Size(150, 40)
$viewPwBtn.Location = New-Object System.Drawing.Point(300, 10)
$viewPwBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$viewPwBtn.BackColor = [System.Drawing.Color]::FromArgb(243, 242, 241)
$viewPwBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$viewPwBtn.Enabled = $false

$selectAllBtn = New-Object System.Windows.Forms.Button
$selectAllBtn.Text = "✓ All"
$selectAllBtn.Size = New-Object System.Drawing.Size(70, 40)
$selectAllBtn.Location = New-Object System.Drawing.Point(460, 10)
$selectAllBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$selectAllBtn.BackColor = [System.Drawing.Color]::FromArgb(243, 242, 241)
$selectAllBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat

$selectNoneBtn = New-Object System.Windows.Forms.Button
$selectNoneBtn.Text = "✗ None"
$selectNoneBtn.Size = New-Object System.Drawing.Size(75, 40)
$selectNoneBtn.Location = New-Object System.Drawing.Point(540, 10)
$selectNoneBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$selectNoneBtn.BackColor = [System.Drawing.Color]::FromArgb(243, 242, 241)
$selectNoneBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat

$exportBtn = New-Object System.Windows.Forms.Button
$exportBtn.Text = "📄 Export CSV"
$exportBtn.Size = New-Object System.Drawing.Size(130, 40)
$exportBtn.Location = New-Object System.Drawing.Point(625, 10)
$exportBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$exportBtn.BackColor = [System.Drawing.Color]::FromArgb(243, 242, 241)
$exportBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$exportBtn.Enabled = $false

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(430, 40)
$progressBar.Location = New-Object System.Drawing.Point(790, 10)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$progressBar.Value = 0

$buttonPanel.Controls.Add($loadBtn)
$buttonPanel.Controls.Add($sendBtn)
$buttonPanel.Controls.Add($viewPwBtn)
$buttonPanel.Controls.Add($selectAllBtn)
$buttonPanel.Controls.Add($selectNoneBtn)
$buttonPanel.Controls.Add($exportBtn)
$buttonPanel.Controls.Add($progressBar)
$Script:Form.Controls.Add($buttonPanel)

$logPanel = New-Object System.Windows.Forms.Panel
$logPanel.Size = New-Object System.Drawing.Size(1220, 160)
$logPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$logPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

$Script:LogBox = New-Object System.Windows.Forms.RichTextBox
$Script:LogBox.Size = New-Object System.Drawing.Size(1220, 160)
$Script:LogBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$Script:LogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$Script:LogBox.ReadOnly = $true
$Script:LogBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$Script:LogBox.ForeColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
$Script:LogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None

$logPanel.Controls.Add($Script:LogBox)
$Script:Form.Controls.Add($logPanel)

function Test-IsValidEmailAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    try {
        $null = [System.Net.Mail.MailAddress]::new($Address)
        return $true
    }
    catch {
        return $false
    }
}

function Sync-UiConfig {
    $previousMailFrom = $Config.MailFrom
    $previousAuthenticatedGraphAccount = $Config.AuthenticatedGraphAccount
    $previousSmtpAuthUser = $Config.SmtpAuthUser

    if ($Script:MailFromTextBox -and -not $Script:MailFromTextBox.IsDisposed) {
        $mailFrom = ([string]$Script:MailFromTextBox.Text).Trim()
        if ([string]::IsNullOrWhiteSpace($mailFrom)) {
            throw "Send As address cannot be blank."
        }
        if (-not (Test-IsValidEmailAddress -Address $mailFrom)) {
            throw "Send As address is not a valid email address: $mailFrom"
        }

        $Config.MailFrom = $mailFrom

        if ([string]::IsNullOrWhiteSpace($Config.SupportEmail) -or $Config.SupportEmail -eq $previousMailFrom) {
            $Config.SupportEmail = $mailFrom
        }
    }

    if ($Script:AuthenticatedGraphAccountTextBox -and -not $Script:AuthenticatedGraphAccountTextBox.IsDisposed) {
        $expectedGraphAccount = ([string]$Script:AuthenticatedGraphAccountTextBox.Text).Trim()
        if ([string]::IsNullOrWhiteSpace($expectedGraphAccount)) {
            throw "Expected Graph login cannot be blank."
        }
        if (-not (Test-IsValidEmailAddress -Address $expectedGraphAccount)) {
            throw "Expected Graph login is not a valid email address: $expectedGraphAccount"
        }

        $Config.AuthenticatedGraphAccount = $expectedGraphAccount

        if ([string]::IsNullOrWhiteSpace($previousSmtpAuthUser) -or $previousSmtpAuthUser -eq $previousAuthenticatedGraphAccount) {
            $Config.SmtpAuthUser = $expectedGraphAccount
        }
    }

    if ($Script:ActivationDelayUpDown -and -not $Script:ActivationDelayUpDown.IsDisposed) {
        $Config.PropagationWaitSeconds = [int]$Script:ActivationDelayUpDown.Value
    }

    if ($Script:RetryDelayUpDown -and -not $Script:RetryDelayUpDown.IsDisposed) {
        $Config.GraphRetryDelaySeconds = [int]$Script:RetryDelayUpDown.Value
    }

    if ($Script:SmtpWaitUpDown -and -not $Script:SmtpWaitUpDown.IsDisposed) {
        $Config.SmtpAuthPropagationWaitSeconds = [int]$Script:SmtpWaitUpDown.Value
    }

    $headerSubLabelControl = $null
    try {
        $headerSubLabelControl = $Script:Form.Controls.Find("HeaderSubLabel", $true) | Select-Object -First 1
    }
    catch {}

    if ($headerSubLabelControl) {
        $headerSubLabelControl.Text = "Flow: generate password → email user → wait $($Config.PropagationWaitSeconds)s → apply password → force password change"
    }
}


# ====================== EVENT HANDLERS ======================
$loadBtn.Add_Click({
    Write-Log "Load Users button clicked" "Info"

    try {
        Sync-UiConfig
        Write-Log "Using Send As address: $($Config.MailFrom) | Expected Graph login: $($Config.AuthenticatedGraphAccount) | Activation delay: $($Config.PropagationWaitSeconds)s | Retry delay: $($Config.GraphRetryDelaySeconds)s | SMTP wait: $($Config.SmtpAuthPropagationWaitSeconds)s" "Info"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            "Invalid Workflow Address Settings",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    if (-not $Script:GraphConnected) {
        $connected = Connect-Graph
        if (-not $connected) { return }
    }

    try {
        Update-Status "Loading users from $($Config.Domain)..."

        $allUsers = Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled,UserType,Id -ErrorAction Stop
        $filteredUsers = @($allUsers | Where-Object {
            $_.UserPrincipalName -like "*@$($Config.Domain)" -and
            $_.AccountEnabled -eq $true -and
            $_.UserType -eq "Member"
        } | Sort-Object DisplayName)

        $signInMap = Get-UserSignInActivityMap

        $Script:DataGridView.Rows.Clear()

        foreach ($user in $filteredUsers) {
            $rowIndex = $Script:DataGridView.Rows.Add()
            $row = $Script:DataGridView.Rows[$rowIndex]
            $row.Cells["Select"].Value = $false
            $row.Cells["DisplayName"].Value = $user.DisplayName
            $row.Cells["UserPrincipalName"].Value = $user.UserPrincipalName
            $row.Cells["Status"].Value = "Ready"

            if ($signInMap.ContainsKey($user.Id)) {
                $row.Cells["LastSignIn"].Value = $signInMap[$user.Id]
            }
            elseif (Has-GraphScope -Scope "AuditLog.Read.All") {
                $row.Cells["LastSignIn"].Value = "No data"
            }
            else {
                $row.Cells["LastSignIn"].Value = "Scope not granted"
            }

            $row.Tag = $user.Id
        }

        $sendBtn.Enabled = ($filteredUsers.Count -gt 0)
        $Script:UsersLoaded = $true
        Update-Status "Loaded $($filteredUsers.Count) users"
        Write-Log "Successfully loaded $($filteredUsers.Count) users" "Success"
    }
    catch {
        Write-Log "Error loading users: $($_.Exception.Message)" "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to load users.`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

$selectAllBtn.Add_Click({
    foreach ($row in $Script:DataGridView.Rows) {
        $row.Cells["Select"].Value = $true
    }
})

$selectNoneBtn.Add_Click({
    foreach ($row in $Script:DataGridView.Rows) {
        $row.Cells["Select"].Value = $false
    }
})

$viewPwBtn.Add_Click({
    if ($Script:PasswordRecords.Count -eq 0) {
        Update-Status "No password records are available yet."
        Write-Log "No password records are available yet." "Info"
        return
    }

    $pwForm = New-Object System.Windows.Forms.Form
    $pwForm.Text = "O365 Batch User Passwords - $($Config.Domain)"
    $pwForm.Size = New-Object System.Drawing.Size(1180, 560)
    $pwForm.StartPosition = "CenterScreen"
    $pwForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $pwForm.TopMost = $true

    $pwGrid = New-Object System.Windows.Forms.DataGridView
    $pwGrid.Size = New-Object System.Drawing.Size(1135, 430)
    $pwGrid.Location = New-Object System.Drawing.Point(20, 20)
    $pwGrid.AllowUserToAddRows = $false
    $pwGrid.AllowUserToDeleteRows = $false
    $pwGrid.ReadOnly = $true
    $pwGrid.SelectionMode = "FullRowSelect"
    $pwGrid.BackgroundColor = [System.Drawing.Color]::White
    $pwGrid.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $pwGrid.AutoSizeColumnsMode = "Fill"

    $pwGrid.Columns.AddRange(
        (New-Object System.Windows.Forms.DataGridViewTextBoxColumn -Property @{ HeaderText = "User"; Name = "User" }),
        (New-Object System.Windows.Forms.DataGridViewTextBoxColumn -Property @{ HeaderText = "Display Name"; Name = "DisplayName" }),
        (New-Object System.Windows.Forms.DataGridViewTextBoxColumn -Property @{ HeaderText = "Temp Password"; Name = "Password" }),
        (New-Object System.Windows.Forms.DataGridViewTextBoxColumn -Property @{ HeaderText = "Status"; Name = "Status" }),
        (New-Object System.Windows.Forms.DataGridViewTextBoxColumn -Property @{ HeaderText = "Transport"; Name = "Transport" }),
        (New-Object System.Windows.Forms.DataGridViewTextBoxColumn -Property @{ HeaderText = "Timestamp"; Name = "Timestamp" }),
        (New-Object System.Windows.Forms.DataGridViewTextBoxColumn -Property @{ HeaderText = "Notes"; Name = "Notes" })
    )

    foreach ($rec in $Script:PasswordRecords) {
        $idx = $pwGrid.Rows.Add()
        $pwGrid.Rows[$idx].Cells["User"].Value = $rec.User
        $pwGrid.Rows[$idx].Cells["DisplayName"].Value = $rec.DisplayName
        $pwGrid.Rows[$idx].Cells["Password"].Value = $rec.Password
        $pwGrid.Rows[$idx].Cells["Status"].Value = $rec.Status
        $pwGrid.Rows[$idx].Cells["Transport"].Value = $rec.Transport
        $pwGrid.Rows[$idx].Cells["Timestamp"].Value = $rec.Timestamp
        $pwGrid.Rows[$idx].Cells["Notes"].Value = $rec.Notes
    }

    $copyBtn = New-Object System.Windows.Forms.Button
    $copyBtn.Text = "📋 Copy Selected Password"
    $copyBtn.Size = New-Object System.Drawing.Size(190, 35)
    $copyBtn.Location = New-Object System.Drawing.Point(20, 465)
    $copyBtn.Add_Click({
        if ($pwGrid.SelectedRows.Count -gt 0) {
            $value = [string]$pwGrid.SelectedRows[0].Cells["Password"].Value
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                [System.Windows.Forms.Clipboard]::SetText($value)
                Update-Status "Password copied to clipboard."
                Write-Log "Password copied to clipboard." "Info"
            }
        }
    })

    $closeBtn = New-Object System.Windows.Forms.Button
    $closeBtn.Text = "Close"
    $closeBtn.Size = New-Object System.Drawing.Size(100, 35)
    $closeBtn.Location = New-Object System.Drawing.Point(1055, 465)
    $closeBtn.Add_Click({ $pwForm.Close() })

    $pwForm.Controls.Add($pwGrid)
    $pwForm.Controls.Add($copyBtn)
    $pwForm.Controls.Add($closeBtn)

    [void]$pwForm.ShowDialog()
})

$sendBtn.Add_Click({
    try {
        Sync-UiConfig
        Write-Log "Workflow sender set to: $($Config.MailFrom) | Expected Graph login: $($Config.AuthenticatedGraphAccount) | Activation delay: $($Config.PropagationWaitSeconds)s | Retry delay: $($Config.GraphRetryDelaySeconds)s | SMTP wait: $($Config.SmtpAuthPropagationWaitSeconds)s" "Info"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            "Invalid Workflow Address Settings",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    if (-not $Script:GraphConnected) {
        [System.Windows.Forms.MessageBox]::Show(
            "Not connected. Click 'Load Users' first.",
            "Not Connected",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    $selectedRows = @($Script:DataGridView.Rows | Where-Object { $_.Cells["Select"].Value -eq $true })
    if ($selectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select at least one user.",
            "No Selection",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    if ($Config.StrictPreflight) {
        Update-Status "Running workflow preflight checks..."
        Write-Log "Running workflow preflight checks before any credential emails are sent..." "Info"
        $preflight = Test-PasswordResetCapability -Rows $selectedRows
        if (-not $preflight.Success) {
            $details = ($preflight.Issues -join "`n• ")
            Write-Log "Workflow preflight failed: $($preflight.Issues -join ' | ')" "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Workflow blocked before sending any password emails.`n`nIssues:`n• $details`n`nConnected account roles: $($preflight.OperatorRoles -join ', ')`n`nReconnect with broader consent and an appropriate Entra admin role, then retry.",
                "Preflight Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        Write-Log "Workflow preflight passed. Operator roles: $($preflight.OperatorRoles -join ', ')" "Success"
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Run the workflow for $($selectedRows.Count) user(s)?`n`nFlow:`n1. Generate password`n2. Email password`n3. Wait $($Config.PropagationWaitSeconds) seconds`n4. Apply password and force password change",
        "Confirm",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
        return
    }

    Write-Log "Starting password workflow for $($selectedRows.Count) users" "Info"

    $sendBtn.Enabled = $false
    $loadBtn.Enabled = $false
    $viewPwBtn.Enabled = $false
    $exportBtn.Enabled = $false
    $progressBar.Value = 0
    $progressBar.Maximum = [Math]::Max(1, $selectedRows.Count)
    $Script:ProcessingResults = @()
    $Script:PasswordRecords = @()
    $Script:CurrentRowIndex = 0

    try {
        foreach ($row in $selectedRows) {
            $upn = [string]$row.Cells["UserPrincipalName"].Value
            Update-Status "Processing $upn"
            Write-Log "Processing row for $upn" "Info"

            $result = Process-UserReset -Row $row
            $Script:ProcessingResults += $result

            $Script:CurrentRowIndex++
            $progressBar.Value = [Math]::Min($Script:CurrentRowIndex, $progressBar.Maximum)
            Pump-UI
        }
    }
    catch {
        Write-Log "Unhandled processing error: $($_.Exception.Message)" "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "An unexpected processing error occurred.`n`n$($_.Exception.Message)",
            "Processing Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    finally {
        $reportPath = $null
        try {
            if ($Script:ResolvedLogPath) {
                $reportPath = Join-Path -Path $Script:ResolvedLogPath -ChildPath ("report_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                $Script:ProcessingResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-Log "Processing report written to $reportPath" "Success"
            }
            else {
                Write-Log "No writable log path was available for the summary report." "Warning"
            }
        }
        catch {
            Write-Log "Failed to write processing report: $($_.Exception.Message)" "Warning"
        }

        $successCount = (@($Script:ProcessingResults | Where-Object { $_.Status -eq 'Success' }).Count)
        $failCount = (@($Script:ProcessingResults | Where-Object { $_.Status -ne 'Success' }).Count)

        Update-Status "Complete - $successCount succeeded, $failCount failed"
        Write-Log "PROCESS COMPLETE - Success: $successCount, Failed: $failCount" "Success"

        $sendBtn.Enabled = $true
        $loadBtn.Enabled = $true
        $viewPwBtn.Enabled = ($Script:PasswordRecords.Count -gt 0)
        $exportBtn.Enabled = ($Script:PasswordRecords.Count -gt 0)

        $msg = "Done!`n`nSuccessful: $successCount`nFailed: $failCount"
        if ($reportPath) {
            $msg += "`n`nReport: $reportPath"
        }

        Update-Status $msg.Replace("`n", " | ")
        Write-Log $msg.Replace("`n", " | ") "Info"
    }
})

$exportBtn.Add_Click({
    if ($Script:PasswordRecords.Count -eq 0) {
        Update-Status "No password records are available to export."
        Write-Log "No password records are available to export." "Info"
        return
    }

    $securityWarning = [System.Windows.Forms.MessageBox]::Show(
        "⚠️ SECURITY WARNING ⚠️`n`nThe exported CSV will contain plaintext temporary passwords.`n`nContinue?",
        "Confirm Export",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($securityWarning -ne [System.Windows.Forms.DialogResult]::Yes) {
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveDialog.FileName = "O365_BatchUserPW_PASSWORDS_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $Script:PasswordRecords |
                Select-Object User, DisplayName, Password, Status, Transport, Timestamp, Notes |
                Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

            Write-Log "Password records exported: $($saveDialog.FileName)" "Success"
            Update-Status "Export complete: $($saveDialog.FileName)"
            Write-Log "Export complete: $($saveDialog.FileName)" "Info"
        }
        catch {
            Write-Log "Failed to export password records: $($_.Exception.Message)" "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Export failed.`n`n$($_.Exception.Message)",
                "Export Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})

# ====================== FORM LIFECYCLE ======================
$Script:Form.Add_Shown({
    $Script:Form.Activate()
    Write-Log "Application started" "Info"
    Write-Log "Resolved log path: $Script:ResolvedLogPath" "Info"
    Write-Log "Expected Graph account: $($Config.AuthenticatedGraphAccount)" "Info"
    Write-Log "Default Send As address: $($Config.MailFrom)" "Info"
    Write-Log "Default expected Graph login: $($Config.AuthenticatedGraphAccount)" "Info"
    Write-Log "Visible mail sender: $($Config.MailFrom)" "Info"
    Write-Log "Activation delay: $($Config.PropagationWaitSeconds)s | Retry delay: $($Config.GraphRetryDelaySeconds)s | SMTP wait: $($Config.SmtpAuthPropagationWaitSeconds)s" "Info"

    if (-not (Test-IsAdministrator)) {
        Write-Log "Script is not running elevated. That is acceptable for Graph operations, but module install / local environment tasks may be more fragile." "Warning"
    }

    Update-Status "Ready - Click 'Load Users'"
})

$Script:Form.Add_FormClosing({
    Write-Log "Closing application..." "Info"
    Disconnect-Graph
    Disconnect-Exchange
    $Script:PasswordRecords = @()
})

# ====================== LAUNCH ======================
try {
    Update-Status "Initializing..."
    [void]$Script:Form.ShowDialog()
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "Error"
    Disconnect-Graph
    Disconnect-Exchange
    [System.Windows.Forms.MessageBox]::Show(
        "Critical error:`n`n$($_.Exception.Message)",
        "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
}
finally {
    Disconnect-Graph
    Disconnect-Exchange
    $Script:PasswordRecords = @()
}
