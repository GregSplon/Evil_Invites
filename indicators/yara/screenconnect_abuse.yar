/*
 * YARA rules — "Special Invitation" campaign ScreenConnect RAT delivery
 *
 * Context: attackers abuse legitimate ConnectWise ScreenConnect SaaS tenants.
 * The installers are digitally signed, stock ScreenConnect Access clients with
 * attacker-tenant relay configuration embedded as plaintext in the binary.
 *
 * FALSE-POSITIVE WARNING: rules match any ScreenConnect installer for the
 * tenant / with guest-access parameters. Legitimate MSP remote-support installs
 * will match the generic rule. Apply an allowlist of sanctioned tenants/hosts.
 *
 * Tested against observed samples (12,809,272-byte PE, version 26.5.3.9691).
 */

rule SC_TenantA_JeaniesJourneys_AccessInstaller {
    meta:
        author = "defensive research"
        description = "ScreenConnect Access client installer embedding jeanies-journeys / instance-s7gewk relay config (tenant A)"
        reference = "https://jeanies-journeys.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest"
        hash = "c68c432515df92ebe29b9eb3dab6a2d2cf1dea292eae3d5f5e081b05ae86f422"
        sc_version = "26.5.3.9691"
        date = "2026-08-24"
        tlp = "WHITE"
    strings:
        $host = "jeanies-journeys.screenconnect.com"
        $relay = "instance-s7gewk-relay.screenconnect.com"
        $settings = "ScreenConnect.ApplicationSettings"
    condition:
        uint16(0) == 0x5A4D and filesize > 10000000 and
        $settings and ($host or $relay)
}

rule SC_TenantB_Ieee2_AccessInstaller {
    meta:
        author = "defensive research"
        description = "ScreenConnect Access client installer embedding ieee2 / instance-ifkw0e relay config (tenant B)"
        reference = "https://ieee2.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest"
        hash = "5d7a14e9719d05b1bd20099923b12e80911f03f989fe18199aa983054cc4605e"
        sc_version = "26.5.3.9691"
        date = "2026-09-04"
        tlp = "WHITE"
    strings:
        $host = "ieee2.screenconnect.com"
        $relay = "instance-ifkw0e-relay.screenconnect.com"
        $settings = "ScreenConnect.ApplicationSettings"
    condition:
        uint16(0) == 0x5A4D and filesize > 10000000 and
        $settings and ($host or $relay)
}

rule SC_GuestAccess_Unattended_Installer_Generic {
    meta:
        author = "defensive research"
        description = "Generic ScreenConnect client installer requesting guest (no-auth) unattended access to an arbitrary tenant"
        reference = "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/understand-the-relationship-between-appcontrol-and-antivirus" // informational
        date = "2026-09-04"
        tlp = "WHITE"
    strings:
        $settings = "ScreenConnect.ApplicationSettings"
        $relay = /instance-[a-z0-9]{4,12}-relay\.screenconnect\.com/
        $access = "e=Access"
        $guest = "y=Guest"
    condition:
        uint16(0) == 0x5A4D and filesize > 10000000 and
        $settings and $relay and 1 of ($access, $guest)
}
