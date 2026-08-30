# pmacct-agent installer (Windows). The Agents page generates, for an administrator PowerShell:
#   [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
#   iex (iwr -UseBasicParsing https://SERVER/api/v1/agent/install.ps1).Content
#   Install-PmacctAgent -Server https://SERVER -Token ENROLL_TOKEN -CaFingerprint AA:BB:… -CaPin base64…
# Trust model: the CA is fetched without validation, checked against -CaFingerprint (given
# out-of-band by the UI) and then imported into the machine's trusted roots — so downloads are
# validated normally, and browsers on this machine trust the analyzer's HTTPS too. The binary is
# checksum-verified and the agent re-verifies -CaPin at enrollment.
function Install-PmacctAgent {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$Token,
        [string]$CaFingerprint = "",
        [string]$CaPin = "",
        [string]$Capture = "auto",
        [switch]$SendCmdline,
        [string]$SpoolDir = ""
    )
    $ErrorActionPreference = "Stop"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "run this from an administrator PowerShell" }
    $Server = $Server.TrimEnd('/')
    $dir = Join-Path $env:ProgramData "pmacct-agent"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    if ($Server.StartsWith("https://")) {
        $caPath = Join-Path $dir "ca.pem"
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        try { Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/v1/tls/ca" -OutFile $caPath } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
        $ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($caPath)
        $got = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($ca.RawData))).Replace("-", ":")
        if ($CaFingerprint) {
            if ($got -ne $CaFingerprint.ToUpper()) { throw "CA fingerprint mismatch: server presented $got, expected $CaFingerprint - aborting" }
            Write-Host "CA fingerprint verified"
        } else {
            Write-Warning "no -CaFingerprint given; trusting the fetched CA on first use ($got)"
        }
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $store.Open("ReadWrite"); $store.Add($ca); $store.Close()
        Write-Host "CA imported into Trusted Root Certification Authorities"
    } else {
        Write-Warning "plain http - the enrollment token crosses the network in clear"
    }
    $exe = Join-Path $dir "pmacct-agent.exe"
    $tmp = Join-Path $dir "pmacct-agent.download"
    Write-Host "downloading pmacct-agent (windows-amd64)..."
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/v1/agent/download/windows-amd64" -OutFile $tmp
    $want = ((Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/v1/agent/download/windows-amd64.sha256").Content -split ' ')[0].Trim().ToLower()
    $have = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
    if ($have -ne $want) { Remove-Item $tmp -Force; throw "checksum mismatch - aborting" }
    $svc = Get-Service -Name pmacct-agent -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { Stop-Service pmacct-agent }
    Move-Item -Force $tmp $exe
    $args = @("enroll", "--server", $Server, "--token", $Token, "--capture", $Capture)
    if ($CaPin) { $args += @("--ca-pin", $CaPin) }
    if ($SendCmdline) { $args += "--send-cmdline" }
    if ($SpoolDir) { $args += @("--spool-dir", $SpoolDir) }
    & $exe @args
    if ($LASTEXITCODE -ne 0) { throw "enrollment failed" }
    if ($svc) { & $exe uninstall | Out-Null }
    & $exe install
    Write-Host "done - the agent should appear online on the Agents page within a minute"
}
