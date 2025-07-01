# YARA-and-Sigma-for-SOC

## Intro
### Notes
- YARA and Sigma are critical tools for SOC analysts (Security Operations Center).
- They enhance threat detection and incident response capabilities.

Key Benefits
- Improved threat detection
- Efficient log analysis
- Malware detection and classification
- IOC identification
- Collaboration and rule sharing
- Customization and integration with other security tools

YARA vs. Sigma
- YARA:
  - Best suited for file and memory analysis
  - Great at pattern matching
- Sigma:
  - Tailored for log analysis
  - Works well with SIEM systems
 
How it Works
- Use detection rules based on conditional logic:
  - Applied to logs (Sigma) or files/memory (YARA)
  - Detects suspicious activities or known patterns

Standardization & Community Use
- Both follow standard rule formats
- Designed to facilitate rule creation and sharing across the cybersecurity community

Importance of YARA and Sigma Rules
- Enhanced Threat Detection
  - Custom detection rules allow SOC analysts to identify patterns, behaviors, or indicators linked to threats.
  - Analysts can proactively detect and respond to incidents.
  - YARA Rule Rources:
    - YARA Malware Rules – Yara-Rules (https://github.com/Yara-Rules/rules/tree/master/malware)
    - Open-Source YARA Rules – MikeSxrs (https://github.com/mikesxrs/Open-Source-YARA-rules/tree/master)
  - Sigma Rule Sources:
    - Sigma Rules – SigmaHQ (https://github.com/SigmaHQ/sigma/tree/master/rules)
    - Joe Security Sigma Rules (https://github.com/joesecurity/sigma-rules)
    - SIGMA Detection Rules – mdecrevoisier (https://github.com/mdecrevoisier/SIGMA-detection-rules)
- Efficient Log Analysis
  - Sigma rules are designed for filtering and correlating logs from various sources.
  - Reduces noise and highlights security-relevant events.
  - Supports faster, focused investigations.
  - Tool Example: Chainsaw (https://github.com/WithSecureLabs/chainsaw) — applies Sigma rules to Windows Event Logs.
- Collaboration and Standardization
  - YARA and Sigma use standardized formats, making rule sharing and collaboration easier.
  - Helps the community develop and share best practices and threat intelligence.
  - Shared rule examples:
    - DFIR YARA Rules (https://github.com/The-DFIR-Report/Yara-Rules)
    - DFIR Sigma Rules (https://github.com/The-DFIR-Report/Sigma-Rules)
- Integration with Security Tools
  - Compatible with SIEMs, EDRs, log analysis tools, and IR platforms.
  - Allows for automation and enrichment of alerts.
  - Tool Example: Uncoder.io (https://uncoder.io/) — converts Sigma rules into SIEM/XDR-ready queries.
- Malware Detection and Classification
  - YARA rules can be used to define malware signatures and detect specific traits or behaviors.
  - Aids in classifying and mitigating malware quickly.
- IOC Identification
  - Both rule types help detect IOCs (e.g., IPs, hashes, domains, filenames).
  - Helps quickly respond to threats and limit attacker dwell time.

## YARA and Rules
### Notes


Overview
- **What is YARA?**
  - A pattern-matching tool and rule format used to identify and classify files based on specific content or characteristics.
- **Primary Use Cases**
  - Detection and classification of malware.
    - Identify malware samples using signatures, behaviors, or file properties.
    - Useful in detecting malicious files and analyzing memory dumps in forensic investigations.
  - Analysis and identification of suspicious files.
    - Categorize files based on attributes such as: file type, format, version, metadata, packers, or other identifiers
    - Especially helpful in malware research and large-scale forensic investigations.
  - Spotting IOCs.
    - Detect known IOCs such as: filenames, registry keys and network indicators
    - Facilitates identification of breaches or ongoing attacks.
  - Memory forensics and threat hunting.
    - Conduct environment-wide scans for: hidden threats or remnants of previous infections
    - Reduces reliance on reactive alerts.
  - Community-Driven Rule Sharing
    - Leverage shared YARA rule sets from the global cybersecurity community.
    - Helps maintain up-to-date detection capabilities.
  - Create Custom Security Solutions
    - Combine YARA rules with: static/dynamic analysis, sandboxing and behavior monitoring
    - Builds stronger, layered detection mechanisms.
  - Custom YARA Rules/Signatures
    - Tailor detection rules for specific organizational needs.
    - Deploy within tools like antivirus or EDR solutions.
    - Detect targeted threats unique to your infrastructure or industry.
  - Incident Response
    - Quickly search memory or files for relevant artifacts during investigations.
    - Helps define the scope and impact of incidents.
- **YARA Rules**
  - Written in a specific syntax.
  - Can include: strings, regular expressions and Boolean logic
  - Supports both textual and binary pattern matching.
- **Application Method**
  - Scans files or directories to match defined patterns.
  - Triggers alerts when conditions are met.
  - Can be integrated into automated security workflows.
- **Key Benefits for SOC Analysts**
  - Enables precise and complex detections.
  - Ideal for malware analysis and forensic investigations.
  - Highly flexible and widely supported in the cybersecurity community.

How Yara Works
- Set of YARA Rules
  - Created by security analysts.
  - Define suspicious patterns or indicators such as: strings, byte sequences and regular expressions
  - Stored in .yar or .yara files for reusability.
- Set of Files for Scanning
  - Input files can be: executables, documents, scripts, memory images or captured network traffic
  - Files are scanned to detect matches with rule-defined patterns.
- YARA Scan Engine
  - Core engine that performs the matching process.
  - Uses YARA modules — internal components that enhance detection through efficient scanning techniques.
- Scanning and Matching Process
  - Engine scans each file byte-by-byte.
  - Applies string matching, regex matching, and binary pattern matching.
  - Compares file contents against the rules for matches.
- Detection of Matches
  - If a file matches a rule’s conditions, it is marked as detected.
  - The engine logs details like: matched rule name, file path and offset (location) of the match within the file
  - Results can be used for alerts, further analysis, or incident response.

YARA Rule Structure

![YARA_Rules3](https://github.com/user-attachments/assets/62f0e9cf-2bba-45a3-8da6-1dfbcb991d0b)

- Each rule in YARA starts with 'rule' keyword, foolowe dby an 'identifier'
  - 'identifier': case sensitive, first character can't be a digit, can't exceed 128 characters
  - 'rule': is a keyword, reserved for a specific use

Rule Breakdown:
- Rule Header: provides metadata and identifies the rule. Typically includes:
  - Rule name: A descriptive name for the rule.
  - Rule tags: Optional tags or labels to categorize the rule.
  - Rule metadata: Additional information such as author, description, and creation date.
- Rule Meta: the definition of additional metadata for the rule. Can include information about the rule's author, references, version, etc.
- Rule Body: contains the patterns or indicators to be matched within the files. This is where the actual detection logic is defined.
- Rule Conditions: define the context or characteristics of the files to be matched. Conditions can be based on file properties, strings, or other indicators. Conditions are specified within the condition section.
  - E.g.
    - 'all of them'
      - It means that all the strings defined in the rule must be present for the rule to trigger a match
    - filesize < 100KB and (uint16(0) == 0x5A4D or uint16(0) == 0x4D5A)
      - File must be less than 100 kilobytes (KB)
      - The first 2 bytes of the file must be either 0x5A4D (ASCII MZ) or 0x4D5A (ASCII ZM), by using uint16(0)
        - uint16: indicates the data type to be extracted, which is a 16-bit unsigned integer (2 bytes).
        - (0): number represents where in the file to start reading, '0' means at the very beginning

## Developing YARA Rules
### Notes
- Conduct a string analysis on the malware sample
  - strings svchost.exe
- File is packed using the UPX (Ultimate Packer for eXecutables)
  - Incorporate UPX-related strings to formulate a basic YARA rule targeting samples packed via UPX
    - E.g. $string_1 = "UPX0", $string_2 = "UPX1", $string_3 = "UPX2"
      - $string_1 = "UPX0": Matches the string UPX0 within the file, etc.
- The UPX_packed_executable rule scans for the strings UPX0, UPX1, and UPX2 inside a file
  - If rule finds all three strings, it raises an alert, hinting that the file might be packed with the UPX packer
  - Useful when on the lookout for executables that have undergone compression or obfuscation using the UPX method

Developing a YARA Rule Through yarGen
- Conduct a string analysis on the malware sample
  - strings dharma_sample.exe
- Can spot 'C:\crysis\Release\PDB\payload.pdb'
- Run yarGen, an automatic YARA rule generator
  - Has the ability to churn out YARA rules based on strings found in malicious files while sidestepping strings common in benign software
  - Comes equipped with a vast database of goodware strings and opcodes
- Install yarGen
  - Download the latest release from the release section
  - Install all dependencies with 'pip install -r requirements.txt'
  - Run 'python yarGen.py --update' to automatically download the built-in databases. They will be saved into the './dbs' subfolder (Download: 913 MB).
  - See help with python yarGen.py --help for more information on the command line parameters.
- Run 'python3 yarGen.py -m /home/htb-student/temp -o htb_sample.yar'
  - yarGen.py: The Python script used to generate YARA rules from sample files.
  - -m /home/htb-student/temp: specifies the input/source directory, where malware or suspicious samples are stored for analysis.
  - -o htb_sample.yar: defines the output file name, the resulting YARA rules will be saved as htb_sample.yar.
- Check the rules
  - cat htb_sample.yar
- Run YARA with the new rule
  - yara htb_sample.yar /home/htb-student/Samples/YARASigma
- Will show multiple .exe files that triggered the rule

Manually Developing a YARA Rule
- Develop rule on a specific variation of the ZoxPNG RAT used by APT17
  - A sample named legit.exe
  - A post from Intezer (https://intezer.com/blog/research/evidence-aurora-operation-still-active-part-2-more-ties-uncovered-between-ccleaner-hack-chinese-hackers-2/)
  - String analysis
  - Imphash
  - Common sample file size
- Run string analysis
  - strings legit.exe
- Use the hashes mentioned in Intezer's post to identify common sample sizes
  - There are no related samples that are bigger than 200KB.
    - https://www.hybrid-analysis.com/sample/ee362a8161bd442073775363bf5fa1305abac2ce39b903d63df0d7121ba60550
- The sample's Imphash can be calculated as follows, using the imphash_calc.py script
- Check the YARA rule for this variation of ZoxPNG
  - apt_apt17_mal_sep17_2.yar
    - YARA Rule Breakdown
      - Rule Imports
        - import "pe"
          - Imports the PE module (Portable Executable).
          - Adds the ability to inspect Windows executable (PE) files in detail.
          - Useful for precise detection in Windows malware.
      - Rule Meta Section
        - description: Describes the rule’s purpose (e.g., detect APT17 malware).
        - license: Indicates the license terms for using the rule.
        - author: Rule created by Florian Roth (Nextron Systems).
        - reference: Link to more info on APT17 or the rule’s background.
        - date: Date of creation or last update: October 3, 2017.
        - hash1, hash2, hash3: Sample hashes of related malware used to build the rule.
      - Rule Body (Strings Section)
        - Contains malware indicators in string format.
        - Two categories:
          - $x* strings: Likely unique or rare indicators.
          - $s* strings: Possibly general or supporting indicators.
      - Rule Condition (Detection Logic)
        - uint16(0) == 0x5a4d: Ensures file starts with MZ — a Windows executable.
        - filesize < 200KB: Limits scanning to files smaller than 200 KB.
        - pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9": Matches a specific import hash, helping to identify similar malware behavior.
        - 1 of ($x*): At least one $x string must match.
        - 6 of them: At least six strings total (from both $x and $s) must be found.

YARA Rule Development Resources
- Official Documentation
  - Most authoritative and comprehensive source.
  - Includes syntax, modules, examples, and rule structuring techniques.
  - https://yara.readthedocs.io/
- Kaspersky Guide
  - Offers practical insights and best practices for writing effective and optimized YARA rules.
  - Good for learning how rules are used in real-world threat detection.
  - https://www.slideshare.net/KasperskyLabGlobal/upping-the-apt-hunting-game-learn-the-best-yara-practices-from-kaspersky
- yarGen Blog Series by Florian Roth
  - A 3-part blog post series on using yarGen to build YARA rules effectively:
    - Part 1: Introduction and basics
      - https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/
    - Part 2: Pattern extraction, cleaning rules
      - https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/
    - Part 3: Advanced adjustments and optimization
      - https://www.nextron-systems.com/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/
- yarGen Tool Overview
  - yarGen automates the extraction of unique patterns from malware samples.
  - It generates draft YARA rules based on these patterns.
  - The generated rules should be manually reviewed for refinement and effectiveness.
  - It strikes a balance between automation and analyst expertise.

### Walkthrough
Q1. Perform string analysis on the "DirectX.dll" sample that resides in the "/home/htb-student/Samples/YARASigma" directory of this section's target. Then, study the "apt_apt17_mal_sep17_1.yar" YARA rule that resides in the "/home/htb-student/Rules/yara" directory and replace "X.dll" with the correct DLL name to ensure the rule will identify "DirectX.dll". Enter the correct DLL name as your answer. Answer format: _.dll
- Run Strings with grep to narrow down the '.dll' mentions since there's too much data for the shell
  - strings /home/htb-student/Samples/YARASigma/DirectX.dll | grep -iE '[a-zA-Z0-9_\-\.]+\.dll'
- Open the YARA rule
  - cat /home/htb-student/Rules/yara/apt_apt17_mal_sep17_1.yar
- Modify the '$s4' from one of the .dll
- Run the rule until the rule is triggered
  - yara /home/htb-student/Rules/yara/apt_apt17_mal_sep17_1.yar /home/htb-student/Samples/YARASigma
- It should show: APT17_Malware_Oct17_1 /home/htb-student/Samples/YARASigma/DirectX.dll
- Answer is: TSMSISrv.dll

## Hunting Evil with YARA (Windows)
### Notes
Hunting for Evil Within ETW Data with YARA
What is ETW?
- ETW (Event Tracing for Windows) is a, general-purpose, high-speed tracing facility built into the Windows OS
- It uses kernel-level buffering and logging to trace events from user-mode applications and kernel-mode device drivers

ETW Components
- Controllers
  - Start/stop trace sessions
  - Enable/disable providers for a session
- Providers
  - Generate and send events to the ETW system
- Consumers
  - Subscribe to and receive specific events
  - Used for processing or analyzing the event data

Useful ETW Providers for Threat Detection
- Process and Execution Monitoring
  - Microsoft-Windows-Kernel-Process
    - Monitors: Process creation/termination
    - Detects: Process injection, hollowing, malware/APT behavior
  - Microsoft-Windows-DotNETRuntime
    - Monitors: .NET application execution
    - Detects: Malicious .NET assemblies, exploitation of .NET vulnerabilities
  - Microsoft-Windows-PowerShell
    - Monitors: PowerShell script execution
    - Detects: Suspicious/malicious scripts, script block logging activity
- File and Registry Monitoring
  - Microsoft-Windows-Kernel-File
    - Monitors: File access and modifications
    - Detects: Unauthorized access, ransomware behavior, critical file changes
  - Microsoft-Windows-Kernel-Registry
    - Monitors: Registry operations
    - Detects: Persistence techniques, malware installations, config changes
- Network Monitoring
  - Microsoft-Windows-Kernel-Network
    - Monitors: Network-level activity
    - Detects: C2 communication, unauthorized connections, exfiltration attempts
  - Microsoft-Windows-SMBClient / SMBServer
    - Monitors: SMB file sharing and communication
    - Detects: Lateral movement, unusual SMB traffic
  - Microsoft-Windows-DNS-Client
    - Monitors: DNS client queries
    - Detects: DNS tunneling, suspicious DNS requests
  - OpenSSH
    - Monitors: SSH sessions
    - Detects: Brute force attacks, failed authentications
  - Microsoft-Windows-VPN-Client
    - Monitors: VPN client events
    - Detects: Suspicious or unauthorized VPN connections
- System Integrity and Security Monitoring
  - Microsoft-Windows-CodeIntegrity
    - Monitors: Code and driver integrity
    - Detects: Unsigned/malicious driver loads
  - Microsoft-Windows-Security-Mitigations
    - Monitors: Security control activity
    - Detects: Bypass attempts of mitigation techniques
  - Microsoft-Antimalware-Service
    - Monitors: Antimalware operations
    - Detects: Disabled protections, configuration tampering
  - Microsoft-Antimalware-Protection
    - Monitors: Antimalware protection mechanisms
    - Detects: Evasion techniques, protection feature changes
- Remote Access and Session Monitoring
  - WinRM (Windows Remote Management)
    - Monitors: Remote management activities
    - Detects: Lateral movement, remote command execution
  - Microsoft-Windows-TerminalServices-LocalSessionManager
    - Monitors: RDP session activity
    - Detects: Unauthorized/suspicious remote desktop connections

YARA Rule Scanning on ETW (Using SilkETW)
- What is SilkETW?
  - An open-source tool designed for working with Event Tracing for Windows (ETW) data.
  - Useful for: security monitoring, threat hunting and incident response
- Key Features
  - Provides enhanced visibility into Windows events.
  - Supports detailed analysis of ETW data.
  - Compatible with a wide variety of ETW providers (e.g., Kernel, PowerShell, DNS).
- YARA Integration
  - Allows YARA rules to be applied directly to ETW event streams.
  - Use cases:
    - Filter ETW events that match specific patterns.
    - Tag suspicious events for further investigation.
  - Enhances the detection of threats by combining behavioral event monitoring with signature-based matching.

### Walkthrough
Q1. Study the "C:\Rules\yara\shell_detector.yar" YARA rule that aims to detect "C:\Samples\MalwareAnalysis\shell.exe" inside process memory. Then, specify the appropriate hex values inside the "$sandbox" variable to ensure that the "Sandbox detected" message will also be detected. Enter the correct hex values as your answer. Answer format: Remove any spaces
- RDP to the machine
- Open the shelldetector.yar with note pad
  - You can see $sandbox is empty
- Open the shell.exe using hexeditor HxD
- 'Ctrl + F' to run Find and type 'Sandbox detected' and click 'Search All'
- It should only return one hit
- Remove the spaces when answering.
- Answer is: 53616E64626F78206465746563746564

## Hunting Evil with YARA (Linux)
### Notes
Memory Forensics with YARA: Overcoming Access Limitations
The Challenge: No Direct Access
- Security Analysts often cannot directly access potentially compromised systems.
  - Reasons: Organizational boundaries, permissions, or logistical limitations.
- This situation is like knowing there's a fire but not being able to reach it.

The Workaround: Memory Capture
- Teams can obtain a memory dump (snapshot of a system's RAM) from the affected system.
- Memory captures provide a full view of system activity at a point in time.
- Analysts can investigate without needing physical access.

The Solution: YARA on Memory Dumps
- YARA can scan memory images for: malware, suspicious patterns, IOCs
- Acts like x-ray vision, giving deep insight into system activity.

Why This Matters
- Ensures remote and inaccessible systems aren’t blind spots.
- Enhances SOC capabilities for threat detection and investigation.
- Shows how YARA enables proactive security analysis even under restrictions.

Memory Scanning Process Overview
- Create YARA Rules
  - Develop your own rules or use existing ones targeting memory-based malware or behaviors.
- Compile YARA Rules (Optional but Recommended)
  - Use the 'yarac' tool to compile rules into a .yrc binary format.
  - Benefits of compiling:
    - Faster performance with large rule sets.
    - Obfuscates rule content, adding a layer of protection.
- Obtain a Memory Image
  - Use memory capture tools like: DumpIt, MemDump, Magnet RAM Capture, Belkasoft RAM Capturer, FTK Imager, LiME (Linux)
- Scan Memory with YARA
  - Run the yara command with either:
    - Compiled rules (.yrc) or
    - Plain text rules (.yar)
  - Scan the captured memory image to detect malware or anomalies.

### Walkthrough
Q1. Study the following resource https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html to learn how WannaCry performs shadow volume deletion. Then, use yarascan when analyzing "/home/htb-student/MemoryDumps/compromised_system.raw" to identify the process responsible for deleting shadows. Enter the name of the process as your answer.
- SSH to the machine.
- Open the link to the resource
  - Look for the 'Table 1: Windows Utilities for VSCs' which will talk about the common utilities used for 'Living Off Land Binaries' technique.
    - In this case this is the technique used.
- Run the yarascan but replace UtilityName with one of the utilities in the table
  - vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "UtilityName"
- Only 1 will trigger the rule.
- When it does, both of the hits shown will have the same 'process'
- Answer is: @WanaDecryptor@

## Hunting Evil with YARA (Web)
### Notes
What Is Unpac.Me?
- A specialized tool for malware unpacking.
- Designed to help analysts analyze and extract behavior or indicators from packed malware samples.

Key Features & Benefits
- YARA Integration
  - Allows you to run your own YARA rules against Unpac.Me's malware sample database.
- Access to a Valuable Dataset
  - Provides free access to a large collection of real-world malware samples.
  - Especially valuable since commercial malware datasets are often restricted or expensive.
- Ideal for:
  - SOC analysts doing threat detection or reverse engineering.
  - Malware researchers looking to test rules or study unpacking behavior.

Why?
- Bridges the gap for those without access to commercial tools or samples.
- A powerful platform to test, validate, and refine YARA rules in real malware environments.

How?
- Register for zero-cost access and hop into the platform.
- Head over to Yara Hunt and choose New Hunt.
- Enter the YARA rule.
- First hit Validate and then Scan.
- Scan the results. Take a quick glance at our example, the system hustled through all malware submissions in a couple of minutes, spotting 1 match.

## Sigma and Sigma Rules
### Notes
What Is Sigma?
- A generic, platform-independent format for writing detection rules.
- Written in YAML format.
- Used to describe log-based detection rules for SIEMs and log analysis tool

Purpose and Use
- Helps SOC analysts detect threats by analyzing log data from sources like: firewalls, IDS/IPS, EDRs, endpoint and server logs
- Rules define conditions and patterns that trigger alerts on suspicious behavior.

Key Features
- Portability: Write once, use across many SIEMs (like Splunk, Elasticsearch, Sentinel, etc.).
- Shareability: Enables easy rule sharing across teams and organizations.
- Customizable: Analysts can tailor rules for specific use cases.
- Supports Detection as Code: Automates creation, testing, and deployment of detection rules.

Integration Benefits
- Can be converted into SIEM-specific queries using tools like sigmac.
- Useful for integrating Indicators of Compromise (IOCs) into automated detection systems.

Sigma Usage
- Universal Log Analytics Tool
  - Write once, deploy anywhere: Sigma rules can be converted to work with multiple SIEM/log tools (e.g., Splunk, Elastic, Sentinel).
  - Eliminates redundancy: Avoids writing detection logic repeatedly for different platforms.
- Community-Driven Rule Sharing
  - Access to shared knowledge: Leverage publicly contributed rules from the Sigma community.
  - Constant updates: Stay current with new detection techniques and emerging threats.
- Incident Response
  - Faster investigations: Use Sigma rules to quickly scan logs for IOCs and suspicious patterns.
  - Focused analysis: Helps narrow down events during an active incident.
- Proactive Threat Hunting
  - Hunt using Sigma patterns: Apply specific detection logic to logs to uncover hidden threats or anomalies.
  - Enhances visibility: Supports hypothesis-driven and indicator-based hunting.
- Integration with Automation Tools
  - Compatible with SOAR: Sigma rules can be converted and integrated into Security Orchestration, Automation, and Response systems.
  - Triggers automated actions: Enables auto-responses based on defined detections.
- Customization for Your Environment
  - Environment-specific tuning: Rules can be customized for your org’s architecture, systems, and known threats.
  - Better relevance: Improves detection accuracy and reduces false positives.
- Gap Identification
  - Compare with community baselines: Identify detection gaps by comparing your rule set with community/shared rules.
  - Prioritize improvements: Focus detection development where coverage is weakest.

How?
- Unified Detection Format
  - Purpose: Sigma provides a standard way to define detection rules for logs.
  - Problem Solved: Replaces scattered, proprietary rule formats with a single, open, structured YAML format.
- YAML-Based Rule Structure
  - Each Sigma rule contains:
    - title: Name of the rule.
    - description: What the rule detects.
    - logsource: Specifies the type of logs (e.g., Windows, Sysmon).
    - detection: The actual pattern or logic to be matched.
- Convertibility Is the Key
  - Sigma is platform-agnostic: It doesn’t run natively in SIEM tools.
  - Instead, it must be converted into SIEM-compatible query language
- Sigma Converter (sigmac)
  - Old standard tool: sigmac converts Sigma rules to specific formats (e.g., ElasticSearch DSL, Splunk SPL, QRadar AQL).
  - Supported platforms: Works with many SIEM/log tools, allowing “write once, use everywhere.”
- pySigma (Modern Replacement)
  - New standard: pySigma is the modern framework for rule translation and tooling.
  - Why it matters: sigmac is now considered outdated — use pySigma for up-to-date, actively maintained conversions.
- Bottom Line
  - Sigma rules describe what to look for in logs.
  - A converter (like pySigma) translates that logic into a format your SIEM or log tool understands.
  - This streamlines detection rule development and allows easy sharing and re-use across environments.

Sigma Rule Breakdown
- title
  - Purpose: A short, descriptive label for the rule.
  - Requirement: Max 256 characters.
  - Best Practice: Clearly state what the rule detects.
- id
  - Purpose: A globally unique identifier for the rule.
  - Format: Typically a UUID v4 (e.g., a1b2c3d4-e5f6-7890-1234-56789abcdef0).
  - Note: Not strictly mandatory but highly recommended.
- logsource
  - Defines the type of logs the rule applies to. It's key to contextualizing the detection logic.
  - Includes:
    - category: General class of product logs (e.g., firewall, web, antivirus).
    - product: Specific product or OS (e.g., windows, apache, checkpoint fw1).
    - service: Subcomponent of the product (e.g., sshd, security, applocker).
    - definition: for further context or clarification.
- detection
  - This is the core logic of the rule — how Sigma determines a match.
  - Search Identifiers: Key-value pairs representing field-value matches in logs.
  - Condition: Boolean logic that defines how the identifiers should be evaluated.
 
Sigma Rules
- Values contained in Sigma rules can be modified by value modifiers
- Modifiers are appended after the field name with a pipe character (|) as separator and can also be chained
- Modifiers are applied in the given order to the value
- Types (https://docs.blusapphire.io/sigma-rules/sigma-detection-attributes):
  - contains: Adds wildcard (*) characters around the value(s)
  - all: Links all elements of a list with a logical "AND" (instead of the default "OR")
  - startswith: Adds a wildcard (*) character at the end of the field value
  - endswith: Adds a wildcard (*) character at the begining of the field value
  - re: This value is handled as regular expression by backends

Search Identifiers
- Lists, which can contain:
  - strings that are applied to the full log message and are linked with a logical OR.
  - maps (see below). All map items of a list are linked with a logical OR.
- Maps: Maps (or dictionaries) consist of key/value pairs, in which the key is a field in the log data and the value a string or integer value. All elements of a map are joined with a logical AND.

### Walkthrough
Q1. Using sigmac translate the "C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml" Sigma rule into the equivalent PowerShell command. Then, execute the PowerShell command against "C:\Events\YARASigma\lab_events_4.evtx" and enter the malicious driver as your answer. Answer format: _.sys
- RDP to the machine
- Run PowerShell as Admin
- Change directory to the sigma tools to invoke sigmac
  - cd C:\Tools\sigma-0.21\tools
- Invoke sigmac on the Sigma rule to generate the PowerShell command
  - python sigmac -t powershell 'C:\Tools\chainsaw\sigma\rules\windows\builtin\windefend\win_defender_threat.yml'
- Run the PowerShell command against the captured events
  - Get-WinEvent -Path C:\Events\YARASigma\lab_events_4.evtx | where {($_.ID -eq "1006" -or $_.ID -eq "1116" -or $_.ID -eq "1015" -or $_.ID -eq "1117") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
- There is only one system driver
- Answer is: mimidrv.sys

## Hunting Evil with Sigma (Chainsaw Edition)
### Notes
Rapid Log Analysis Without a SIEM
- Speed is critical in cybersecurity for timely threat detection and response.
- Challenge: Searching through massive Windows Event Logs without a SIEM can be difficult and time-consuming.
- Solution: Use Sigma rules with tools like Chainsaw and Zircolite.

Benefits of Chainsaw & Zircolite
- Allows scanning of multiple EVTX files at once.
- Support Sigma rule integration for detection logic.
- Enable efficient and comprehensive log analysis without relying on a SIEM.
- Ideal for incident response and threat hunting in resource-limited environments.

### Walkthrough
Q1. Use Chainsaw with the "C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml" Sigma rule to hunt for suspicious Defender exclusions inside "C:\Events\YARASigma\lab_events_5.evtx". Enter the excluded directory as your answer.
- RDP to the machine
- Run PowerShell as Admin
- Change directory to the chainsaw tools
  - cd C:\Tools\chainsaw
- Run the Chainsaw command
  - .\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_5.evtx -s C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_win_defender_exclusions_added.yml --mapping .\mappings\sigma-event-logs-all-new.yml
- Answer is: c:\document\virus\

## Hunting Evil with Sigma (Splunk  Edition)
### Notes
Sigma: The Rosetta Stone for SIEMs
- Sigma rules transform how we conduct log analysis and threat detection.
- Think of Sigma as a universal translator for event logs—removing the need to learn SIEM-specific query languages (e.g., Splunk SPL, Elastic DSL, etc.).
- This abstraction layer simplifies writing and sharing detection logic across various platforms.

Validation via Conversion
- You can convert Sigma rules into formats like Splunk SPL to test and validate their effectiveness.
- Comparing original Sigma logic to converted SIEM queries helps verify that:
  - The rules are accurate.
  - The detections behave as intended.

### Walkthrough
Q1. Using sigmac translate the "C:\Rules\sigma\file_event_win_app_dropping_archive.yml" Sigma rule into the equivalent Splunk search. Then, navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and submit the Splunk search sigmac provided. Enter the TargetFilename value of the returned event as your answer.
- Open machine from previous section [Hunting Evil with Sigma (Chainsaw Edition)]
- RDP to machine
- Run PowerShell as Admin
- Change directory to the sigma tools to invoke sigmac
  - cd C:\Tools\sigma-0.21\tools
- Run sigmac to generate a Splunk query version of the rules
  - python sigmac -t splunk C:\Rules\sigma\file_event_win_app_dropping_archive.yml -c .\config\splunk-windows.yml
- Copy the output to a Notepad
  - ((Image="*\\winword.exe" OR Image="*\\excel.exe" OR Image="*\\powerpnt.exe" OR Image="*\\msaccess.exe" OR Image="*\\mspub.exe" OR Image="*\\eqnedt32.exe" OR Image="*\\visio.exe" OR Image="*\\wordpad.exe" OR Image="*\\wordview.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe" OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\finger.exe" OR Image="*\\notepad.exe" OR Image="*\\AcroRd32.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\mshta.exe" OR Image="*\\hh.exe" OR Image="*\\sharphound.exe") (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z" OR TargetFilename="*.diagcab" OR TargetFilename="*.appx"))
- Open a new machine in the current section [Hunting Evil with Sigma (Splunk  Edition)]
- Open FireFox and go to Splunk
  - http://[Target IP]:8000
- Click 'Search & Reporting', paste the generated Splunk query and set the range to 'All Time'
  - There should only be 1 event that triggers the rules
- Answer is: C:\Users\waldo\Downloads\20221108112718_BloodHound.zip



