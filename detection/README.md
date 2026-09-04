# Detection & Hunt Queries

## 1. KQL (Microsoft 365 Defender / Sentinel)

### Email — campaign IOCs in inbound mail

The following Advanced Hunting query is directly runnable against `EmailEvents` + `EmailUrlInfo` and correlates URL indicators by `NetworkMessageId`.

```kusto
let CampaignHosts = dynamic([
    "jeanies-journeys.screenconnect.com",
    "ieee2.screenconnect.com",
    "instance-s7gewk-relay.screenconnect.com",
    "instance-ifkw0e-relay.screenconnect.com",
    "acodcadohappiness.icu",
    "fbends.icu",
    "nav-adv0cati0n.im",
    "pub-58388a1519064228b441a5517c701114.r2.dev"
]);
let CampaignSubjects = dynamic([
    "PLEASE KINDLY OPEN AND DOWNLOAD YOUR SPECIAL INVITE",
    "INVITATION EXTENDED",
    "A DISTINGUISHED INVITATION",
    "SPECIAL INVITATION FROM",
    "SAVE THE DATE",
    "JOIN US"
]);
let CampaignSenders = dynamic([
    "sender-a@example.invalid",
    "sender-b@example.invalid",
    "sender-c@example.invalid",
    "forwarder-a@example.invalid",
    "forwarder-b@example.invalid"
]);
let UrlHits =
    EmailUrlInfo
    | where Timestamp > ago(14d)
    | where Url has_any (CampaignHosts)
    | summarize CampaignUrls = make_set(Url, 20) by NetworkMessageId;
EmailEvents
| where Timestamp > ago(14d)
| join kind=leftouter UrlHits on NetworkMessageId
| where SenderFromAddress in (CampaignSenders)
    or Subject has_any (CampaignSubjects)
    or array_length(CampaignUrls) > 0
| project Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress,
          SenderDisplayName, Subject, DeliveryAction, DeliveryLocation, CampaignUrls
| order by Timestamp desc
```

### Email attachment — ScreenConnect installer names

```kusto
EmailAttachmentInfo
| where Timestamp > ago(14d)
| where FileName startswith "ScreenConnect.ClientSetup"
| project Timestamp, NetworkMessageId, FileName, SHA256, FileSize, ThreatTypes
| order by Timestamp desc
```

### Endpoint — ScreenConnect client artifacts

```kusto
// Process execution of installer/client
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName startswith "ScreenConnect.ClientSetup"
   or FileName startswith "ScreenConnect.ClientService"
   or ProcessCommandLine contains "ScreenConnect.ClientSetup"
| project Timestamp, DeviceName, AccountName, FileName, SHA256,
          ProcessCommandLine, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

```kusto
// Service-install / persistence artifacts containing ScreenConnect
DeviceEvents
| where Timestamp > ago(14d)
| where AdditionalFields contains "ScreenConnect"
| project Timestamp, DeviceName, ActionType, AccountName, AdditionalFields
| order by Timestamp desc
```

```kusto
// Network egress to campaign-specific ScreenConnect tenants/relays
let CampaignHosts = dynamic([
    "jeanies-journeys.screenconnect.com",
    "ieee2.screenconnect.com",
    "instance-s7gewk-relay.screenconnect.com",
    "instance-ifkw0e-relay.screenconnect.com"
]);
let CampaignIPs = dynamic([
    "148.113.219.237",
    "15.235.110.92",
    "40.160.1.134",
    "15.204.129.194"
]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (CampaignHosts) or RemoteIP in (CampaignIPs)
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP,
          RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

> **Allowlisting guidance:** do not suppress an event merely because the binary is signed by ConnectWise or runs from a normal ScreenConnect install path. The abuse uses the legitimate client. Suppress only after validating that the **specific tenant/relay** is sanctioned for the environment.

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

- Enable EventID 1 (process creation), 3 (network), 11 (file create), 13 (registry), plus Windows service-install logging (7045/4697).
- Hunt for `ScreenConnect.ClientSetup*` in Downloads/Temp and `ScreenConnect.ClientService.exe` beneath ScreenConnect client installation directories.
- Treat signer/path legitimacy as context, not exoneration.

## 4. Mail-flow / gateway rules

- Rewrite, sandbox, or quarantine inbound links matching `*.screenconnect.com/Bin/ScreenConnect.ClientSetup.*?e=Access&y=Guest` unless the specific tenant is sanctioned.
- Quarantine mail matching campaign sender/subject/URL combinations.
- Treat SPF/DKIM/DMARC pass as **not** exonerating for this campaign because legitimate accounts were abused.
- Higher-confidence behavioral condition: Evite/Punchbowl-branded mail whose normal brand assets/tool links remain genuine but whose primary CTA points to a third-party credential page or ScreenConnect installer.

## 5. YARA / Sigma

See `../indicators/yara/` and `../indicators/sigma/`. YARA requires PE files. Sigma covers process creation, service install, and network egress. **Allowlist sanctioned tenants, not merely sanctioned binaries or install paths.**
