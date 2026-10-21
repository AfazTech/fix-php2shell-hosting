# PHP2Shell Hosting Security Fix

**Temporary PHP2Shell mitigation for cPanel and DirectAdmin hosting servers using ModSecurity.**

`fix-php2shell-hosting` is an interactive Bash security tool designed to help hosting administrators apply targeted ModSecurity protection and selected security hardening measures while permanent PHP security updates are being deployed.

## Quick Start

Run the following command as `root` on a supported Linux hosting server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AfazTech/fix-php2shell-hosting/main/fix.sh)
```

Alternatively, download the script first, review it, and then execute it:

```bash
curl -fsSLo fix.sh https://raw.githubusercontent.com/AfazTech/fix-php2shell-hosting/main/fix.sh
less fix.sh
chmod 700 fix.sh
./fix.sh
```

The script detects cPanel or DirectAdmin, presents the applicable operations, and asks for confirmation before performing individual changes.

**Requirements:** Root privileges and a supported Linux hosting environment. Some operations require ModSecurity, CSF, Python 3, or panel-specific utilities.

> **Important:** This is a temporary mitigation tool, not a replacement for official PHP security updates. Review and test the script before running it on production servers.

---

## Overview

PHP2Shell is the name used for the PHP security issue targeted by this mitigation. Vulnerabilities that permit unintended command execution through a PHP application or runtime can create serious risks for shared hosting infrastructure.

On multi-tenant hosting servers, a successful exploit may threaten websites, hosting accounts, application data, and server resources, depending on the vulnerability and execution context.

This project provides an interactive way to deploy a targeted ModSecurity rule and apply selected hosting panel hardening measures without manually editing every supported configuration file.

The primary goal is to help hosting administrators reduce exposure during incident response or while preparing permanent vendor-recommended remediation.

**Repository:** https://github.com/AfazTech/fix-php2shell-hosting

**Main script:** `fix.sh`

**Implementation:** Bash

**Target platforms:** cPanel and DirectAdmin hosting servers

**Security mechanism:** ModSecurity request filtering and selected panel hardening measures

## Key Features

- **Targeted ModSecurity mitigation:** Installs a rule intended to block matching multipart requests containing the targeted PHP session upload progress field.
- **cPanel security hardening:** Offers to disable phpMyAdmin through feature lists and disable Roundcube.
- **DirectAdmin security hardening:** Offers to remove the configured DirectAdmin TCP port from the CSF `TCP_IN` list.
- **Automatic panel detection:** Detects cPanel or DirectAdmin based on installed panel directories.
- **Web server detection:** Checks active LiteSpeed and Apache service variants.
- **ModSecurity availability checks:** Attempts panel-specific installation or enablement when ModSecurity is not detected.
- **Configuration backups:** Saves backups of managed configuration files before supported modifications.
- **Apache configuration validation:** Tests Apache configuration before completing the ModSecurity rule deployment.
- **Controlled service restarts:** Restarts relevant services after changes and offers precautionary restarts for previously applied steps.
- **Interactive operation selection:** Administrators can approve or skip individual operations.
- **Duplicate rule ID detection:** Checks selected configuration paths for conflicting uses of the managed rule ID.
- **Execution summary:** Reports completed, already-applied, skipped, and failed operations.
- **Basic rollback handling:** Attempts to restore managed ModSecurity files when configuration validation or the web server restart fails.

## Vulnerability Scope

This repository is intended for a specific PHP2Shell-related mitigation scenario. The exact vulnerability scope and effectiveness must be confirmed against the relevant PHP security advisory.

Related CVE identifiers, if applicable to the issue being addressed:

- CVE-2026-109618
- CVE-2026-109619

Do not assume that a rule matching a particular request parameter fully mitigates either CVE without verifying the official vulnerability details and affected versions.

A ModSecurity rule can reduce exposure to a known request pattern, but it cannot guarantee protection against every exploit variation, alternative request encoding, or unrelated vulnerability.

For permanent remediation, consult official PHP security announcements and the security advisories published by your operating system and hosting panel vendors.

## How the Script Works

### 1. Hosting Panel Detection

The script checks for the following installation directories:

- `/usr/local/cpanel`
- `/usr/local/directadmin`

It selects the corresponding set of panel-specific operations.

### 2. cPanel Hardening

On detected cPanel systems, the script offers two configuration changes.

#### Disable phpMyAdmin

The script modifies cPanel feature lists under:

`/var/cpanel/features/`

It sets the `phpmyadmin` feature to `0` in the detected feature list files.

This is intended to disable the feature through cPanel's feature management system. Administrators should verify the resulting behavior and account-level feature configuration after deployment.

#### Disable Roundcube

The script updates:

`/var/cpanel/cpanel.config`

It sets:

`skiproundcube=1`

This requests server-wide Roundcube disabling through the cPanel configuration mechanism.

These measures reduce access to selected web applications but do not patch PHP itself.

### 3. DirectAdmin Hardening

On detected DirectAdmin systems, the script can modify the CSF firewall configuration.

It reads the configured DirectAdmin port from:

`/usr/local/directadmin/conf/directadmin.conf`

If no valid port is detected, the script falls back to `22222`.

It then offers to remove that port from the `TCP_IN` list in:

`/etc/csf/csf.conf`

CSF is reloaded after a successful change.

**Warning:** Removing the port from `TCP_IN` can interrupt administrative access. Review firewall rules, allowlists, IPv6 exposure, and alternative management access before confirming this operation.

This action restricts the selected firewall entry; it does not disable DirectAdmin, phpMyAdmin, or Roundcube as applications.

### 4. ModSecurity Availability

The script checks whether the relevant Apache ModSecurity module is loaded.

If it is not detected, the script offers a panel-specific installation attempt:

- DirectAdmin: uses CustomBuild.
- cPanel: attempts to install the configured EasyApache-related ModSecurity package.

Installation behavior depends on the server's package repositories, panel version, web server integration, and existing configuration.

A successful package installation alone does not guarantee that ModSecurity is active in the web server handling customer traffic.

### 5. ModSecurity Rule Deployment

The script manages a custom rule file named:

`infraguard.conf`

The rule uses ID:

`501500`

The current rule targets multipart requests containing the field name:

`php_session_upload_progress`

Matching requests are intended to receive HTTP `403 Forbidden`.

The script selects a configuration location based on the detected hosting panel and available ModSecurity include configuration. It also checks selected configuration directories for an existing use of the same rule ID.

Before completing the deployment, it attempts to validate the Apache configuration.

**Important:** A successful syntax check does not prove that the rule detects the intended exploit. Verify the rule against controlled test requests, inspect ModSecurity audit logs, and test legitimate multipart uploads before relying on it.

### 6. Service Restarts

Depending on the operations performed, the script may restart:

- CSF
- cPanel `cpsrvd`
- DirectAdmin
- The detected web server service

When the ModSecurity deployment is considered already applied, the script may offer precautionary restarts.

Service behavior varies across installations. Verify service health and administrative access after execution.

## Supported Environments

The script is designed for Linux hosting environments with one of the following control panels:

| Component | Intended support |
|---|---|
| cPanel | Panel feature list and configuration changes |
| DirectAdmin | CustomBuild and firewall-related operations |
| Apache | ModSecurity module detection and configuration testing |
| LiteSpeed | Service detection and ModSecurity-related rule deployment |
| CSF | Optional DirectAdmin port modification |
| Bash | Main implementation |
| Python 3 | Required for the CSF port-list modification |

The script requires root privileges.

Compatibility is not guaranteed for every distribution, panel release, web server configuration, ModSecurity engine, or firewall setup. Validate each supported operation on your actual server before production use.

## Installation and Execution

### Option A: Direct Execution

The quick-start command downloads the current `fix.sh` from the repository and passes it to Bash.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AfazTech/fix-php2shell-hosting/main/fix.sh)
```

Use this approach only after reviewing and trusting the published script.

### Option B: Download and Review

Download the script:

```bash
curl -fsSLo fix.sh https://raw.githubusercontent.com/AfazTech/fix-php2shell-hosting/main/fix.sh
```

Inspect its contents:

```bash
less fix.sh
```

Make it executable:

```bash
chmod 700 fix.sh
```

Execute it as root:

```bash
./fix.sh
```

For an administrative account that has sudo privileges, use the appropriate root execution method for your environment.

### Interactive Prompts

The script uses the following responses:

- `y` — Approve the operation.
- `s` — Skip the operation.

Read each prompt carefully. Some operations can modify the firewall, disable panel features, install packages, or restart services.

## Backups and Recovery

The script creates timestamped backups under `/root/`, using directories such as:

`/root/server-hardening-backup-YYYYMMDD-HHMMSS`

For example, a backup directory may contain copies of the original configuration files with their paths preserved.

Backups are intended to support manual recovery if a configuration change needs to be reversed.

Before deployment:

1. Verify that the backup location is writable.
2. Confirm that the expected original files have been backed up.
3. Maintain independent administrative access.
4. Record the original service and firewall state.
5. Prepare a recovery procedure appropriate for the server.

The current rollback mechanism covers selected ModSecurity file changes. It does not guarantee a full system rollback, nor does it reverse every package installation, CustomBuild action, firewall modification, or service-side effect.

## Security Best Practices

For production hosting infrastructure, follow these precautions:

- Review the entire script before executing it as root.
- Test the changes on a staging server first.
- Maintain an independent SSH session or console connection.
- Confirm that firewall changes will not lock out administrators.
- Validate ModSecurity behavior with positive and negative test cases.
- Review web server error logs and ModSecurity audit logs.
- Monitor legitimate website uploads after applying the rule.
- Keep configuration backups in a separate, protected location when practical.
- Apply official PHP security updates as soon as they are available.
- Reassess or remove temporary rules when permanent remediation has been completed.

Disabling phpMyAdmin or Roundcube and restricting access to the control panel can reduce certain attack surfaces, but neither measure is a substitute for patching vulnerable PHP versions.

## Limitations

This project is a targeted, interactive mitigation utility. It is not a comprehensive vulnerability scanner, a malware removal tool, or a replacement for system patch management.

It does not guarantee that:

- Every vulnerable PHP installation has been identified.
- Every possible exploit variation is blocked.
- ModSecurity is correctly enabled in every virtual host.
- All changes can be automatically reversed.
- The selected firewall changes preserve every administrative access path.
- The server is secure after the script completes.

A successful run should always be followed by configuration verification, application testing, and permanent remediation.

## Troubleshooting

### ModSecurity Is Not Loaded

Check the web server's active configuration and installed ModSecurity packages. Confirm that the module is loaded in the server instance serving the affected websites.

### Apache Configuration Test Fails

Review the reported configuration error and inspect the changed include file and rule file. Do not restart the web server until the configuration problem has been resolved.

### DirectAdmin Access Is Lost

Use an independent console or other authorized recovery channel to inspect CSF rules and restore the required management access.

### Legitimate Uploads Return HTTP 403

Inspect ModSecurity audit logs to identify the matching rule and request parameters. Confirm that the rule is not blocking legitimate application behavior.

### A Rule ID Conflict Is Reported

Locate the existing rule using ID `501500`. Resolve the conflict before installing another rule with the same ID.

## Contributing

Contributions, bug reports, compatibility findings, and tested improvements are welcome.

When reporting a problem, include:

- Operating system and version.
- Hosting panel and version.
- Web server and version.
- ModSecurity engine and version.
- Relevant sanitized error messages.
- The operation that failed and its resulting status.

Do not include customer data, credentials, private keys, access tokens, or sensitive server configuration details.

## License

No license bro:)

---

**Project:** [AfazTech/fix-php2shell-hosting](https://github.com/AfazTech/fix-php2shell-hosting)

**Purpose:** Temporary PHP2Shell-related security mitigation for cPanel and DirectAdmin hosting servers.

**Reminder:** Apply official security updates and verify the effectiveness of the mitigation in your own environment.