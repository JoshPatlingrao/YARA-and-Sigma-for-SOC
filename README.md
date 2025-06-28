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
