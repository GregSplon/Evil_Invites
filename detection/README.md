# Detection & Hunt Queries

## 1. KQL (Microsoft 365 Defender / Sentinel)

### Email — campaign IOCs in inbound mail (Advanced Hunting: EmailEvents)
```kusto
let urls = dynamic(["jeanies-journeys.screenconnect.com","ieee2.screenconnect.com",
                    "instance-s7gewk-relay.screenconnect.com","instance-ifkw0e-relay.screenconnect.com",
                    "acodcadohappiness.icu","fbends.icu","nav-adv0cati0n.im",
                    "pub-58388a1519064228b441a5517c701114.r2.dev"]);
let subs = dynamic(["PLEASE KINDLY OPEN AND DOWNLOAD YOUR SPECIAL INVITE",
                    "INVITATION EXTENDED", "A DISTINGUISHED INVITATION",
                    "SPECIAL INVITATION FROM", "SAVE THE DATE", "JOIN US"]);
EmailEvents
| where Timestamp > ago(14d)
| where SenderFromAddress in ("search4cm@gmail.com","ndbisongirl@gmail.com","zavfranck@gmail.com","littleann.schweitz06@gmail.com","jacinta58103@yahoo.com")
   or Subject has_any (subs)
   or UrlMatchesAny(EmailUrlInfo, urls) // see EmailUrlInfo join below
```
> Note: join `EmailEvents | join EmailUrlInfo on NetworkMessageId` to match URLs, and `EmailAttachmentInfo` for installer filename `ScreenConnect.ClientSetup`.

### Endpoint — ScreenConnect client artifacts (DeviceProcessEvents / DeviceNetworkEvents / DeviceEvents)
```kusto
// Process execution of the installer
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName startswith "ScreenConnect.ClientSetup"
   or ProcessCommandLine contains "ScreenConnect.ClientSetup"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName

// Service creation (persistence)
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("ServiceCreation","ServiceInstalled")
   or AdditionalFields contains "ScreenConnect"
| project Timestamp, DeviceName, ActionType, AdditionalFields

// Network egress to campaign tenants
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl endswith ".screenconnect.com"
    or RemoteIP in ("148.113.219.237","15.235.110.92","40.160.1.134","15.204.129.194")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

## 2. Splunk (Endpoint TA / Sysmon)

```spl
index=endpoint (Image=*ScreenConnect.ClientSetup.exe OR Image=*ScreenConnect.ClientSetup.msi)
  OR (EventCode=7045 ServiceName=*ScreenConnect*)
  OR (EventCode=4697 ServiceName=*ScreenConnect*)
  OR (EventCode=3 dest_ip IN (148.113.219.237,15.235.110.92,40.160.1.134,15.204.129.194))
  OR (EventCode=3 query IN (*jeanies-journeys.screenconnect.com,*ieee2.screenconnect.com,*instance-s7gewk-relay.screenconnect.com,*instance-ifkw0e-relay.screenconnect.com))
| table _time, host, user, Image, CommandLine, ServiceName, dest_ip, query
```

## 3. Sysmon config hint

- Enable EventID 1 (process creation), 3 (network), 6 (driver/image load — 12.8 MB signed EXE loaded from Downloads/Temp), 13 (registry), 11 (file create for `ScreenConnect.ClientSetup*`).
- Image load logging (EventID 6) catches `ScreenConnect.ClientService.exe` from `%ProgramFiles(x86)%\ScreenConnect Client*`.

## 4. Mail-flow / gateway rules

- Rewrite or sandbox ALL links pointing at `*.screenconnect.com/Bin/ScreenConnect.ClientSetup.*?e=Access&y=Guest` unless the org can prove a sanctioned MSP relationship.
- Quarantine mail matching the sender + subject IOC table.
- Treat SPF/DKIM/DMARC pass as **not** exonerating for this campaign (compromised legitimate senders).

## 5. YARA / Sigma

See `../indicators/yara/` and `../indicators/sigma/`. YARA requires PE files (installer). Sigma covers process creation, service install, and network egress. **Allowlist sanctioned tenants** to avoid false positives on legitimate ConnectWise Control usage.
