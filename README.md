# CMMC-Security-Compliance-Assessment

# CMMC 2.0 Level 1 Security Assessment - Michael Scott Paper Company

## **Overview**
This project is an in-depth **Cybersecurity Maturity Model Certification (CMMC) 2.0 Level 1** security assessment conducted for the **Michael Scott Paper Company**(scenario). The objective of the assessment was to evaluate the organization's compliance with **CMMC 2.0 Level 1** security controls and identify vulnerabilities in areas such as **Access Control, Identification & Authentication, Media Protection, Physical Security, System & Communication Protection, and System & Information Integrity**.

## **Contributors**
- **Reuben Thomas Aravindha**
- **Hariharan M**
- **Bhavin Panchal**
- **Pranay Venkata Bhamidipati**

## **Table of Contents**
- [Introduction](#introduction)
- [Assessment Scope](#assessment-scope)
- [Key Findings](#key-findings)
- [Security Controls Evaluated](#security-controls-evaluated)
- [Methodology](#methodology)
- [Recommendations](#recommendations)
- [Implementation Steps](#implementation-steps)
- [References](#references)

---

## **Introduction**
This project was conducted as part of the **ENPM685 - Security Tools for Information Security** coursework at the **University of Maryland (UMD)**. The **Cybersecurity Maturity Model Certification (CMMC) 2.0** is a framework established by the **U.S. Department of Defense (DoD)** to secure Federal Contract Information (FCI) and Controlled Unclassified Information (CUI). This assessment examines whether the **Michael Scott Paper Company** (scenario) meets the **CMMC 2.0 Level 1** requirements, which focus on **basic cybersecurity hygiene**.

## **Assessment Scope**
- Evaluation of **Access Control (AC), Identification and Authentication (IA), Media Protection (MP), Physical Protection (PE), System and Communications Protection (SC), and System and Information Integrity (SI)**.
- **Identification of vulnerabilities** within internal and external network boundaries.
- **Testing of authentication mechanisms, access controls, and logging practices**.
- **Recommendations for remediation** to ensure compliance with **CMMC 2.0 Level 1**.

## **Key Findings**
The assessment revealed several **security gaps** in the organization’s security posture:
1. **Access Control Weaknesses**
   - Overly permissive directory access (`/var/www/html/uploads`) exposing sensitive FCI data.
   - Lack of firewall restrictions on external connections.
   
2. **Authentication & Identity Management Issues**
   - Weak password policies leading to susceptibility to brute-force attacks.
   - Lack of authentication mechanisms for publicly accessible resources.

3. **Media Protection Gaps**
   - No formal procedures for **secure media disposal** (e.g., certificates of destruction).
   
4. **Physical Security Weaknesses**
   - No physical access logs to track personnel entering restricted zones.
   - No visitor tracking mechanisms such as CCTV surveillance or visitor badges.

5. **System & Communications Protection Deficiencies**
   - No **firewall rules** restricting inbound and outbound traffic.
   - Use of **unencrypted HTTP protocol**, allowing potential eavesdropping.

6. **System & Information Integrity Concerns**
   - Lack of **automated vulnerability remediation processes**.
   - Insufficient **malicious code scanning and real-time protection**.

---

## **Security Controls Evaluated**
| **Category** | **Control ID** | **Description** | **Status** |
|-------------|--------------|--------------|-------------|
| **Access Control (AC)** | AC.L1-3.1.1 | Authorized Access Control | 🔴 Not Met |
| | AC.L1-3.1.2 | Transaction & Function Control | ✅ Met |
| | AC.L1-3.1.20 | External Connections | 🔴 Not Met |
| | AC.L1-3.1.22 | Control Public Information | 🔴 Not Met |
| **Identification & Authentication (IA)** | IA.L1-3.5.1 | Identification | ✅ Met |
| | IA.L1-3.5.2 | Authentication | 🔴 Not Met |
| **Media Protection (MP)** | MP.L1-3.8.3 | Media Disposal | 🔴 Not Met |
| **Physical Protection (PE)** | PE.L1-3.10.1 | Limit Physical Access | 🔴 Not Met |
| | PE.L1-3.10.3 | Escort Visitors | 🔴 Not Met |
| | PE.L1-3.10.4 | Physical Access Logs | 🔴 Not Met |
| | PE.L1-3.10.5 | Manage Physical Access | 🔴 Not Met |
| **System & Communications Protection (SC)** | SC.L1-3.13.1 | Boundary Protection | 🔴 Not Met |
| | SC.L1-3.13.5 | Public-Access System Separation | 🔴 Not Met |
| **System & Information Integrity (SI)** | SI.L1-3.14.1 | Flaw Remediation | 🔴 Not Met |
| | SI.L1-3.14.2 | Malicious Code Protection | 🔴 Not Met |
| | SI.L1-3.14.4 | Update Malicious Code Protection | ✅ Met |
| | SI.L1-3.14.5 | System & File Scanning | 🔴 Not Met |

---

## **Methodology**
1. **Security Configuration Review** – Examined **firewall rules, access control lists (ACLs), and authentication mechanisms**.
2. **Penetration Testing** – Identified **unauthorized access vulnerabilities, weak credentials, and misconfigured permissions**.
3. **Log Analysis** – Reviewed **system and physical access logs** for evidence of security monitoring.
4. **Compliance Mapping** – Mapped findings to **CMMC 2.0 Level 1** requirements.
5. **Recommendations & Remediation Planning** – Proposed solutions to **improve security posture and achieve compliance**.

---

## **Recommendations**
### **1️⃣ Access Control Enhancements**
✅ **Restrict permissions** for **sensitive directories** like `/var/www/html/uploads`.  
✅ **Implement a firewall** with **strict inbound and outbound filtering**.  
✅ **Enforce Role-Based Access Control (RBAC)** to limit user privileges.  

### **2️⃣ Authentication Hardening**
✅ **Enforce strong password policies** and require **MFA for all users**.  
✅ **Restrict authentication attempts** to prevent brute-force attacks.  

### **3️⃣ Media Protection Measures**
✅ **Implement secure media destruction policies** and maintain **audit logs**.  

### **4️⃣ Strengthening Physical Security**
✅ **Maintain access logs** using **biometric authentication or electronic cards**.  
✅ **Implement visitor ID badges & CCTV monitoring**.  

### **5️⃣ Network & Communications Protection**
✅ **Encrypt web traffic using HTTPS (TLS 1.2/1.3)**.  
✅ **Restrict open ports and enforce inbound/outbound firewall rules**.  
✅ **Deploy a corporate VPN** for secure external access.  

### **6️⃣ Malicious Code & Threat Management**
✅ **Enable real-time antivirus scanning** for **uploaded and downloaded files**.  
✅ **Deploy a SIEM solution** for **centralized log monitoring and threat detection**.  
✅ **Automate vulnerability management and remediation**.  

---

## **Implementation Steps**
1. **Update firewall rules** and block all **unauthorized inbound/outbound connections**.
2. **Harden authentication** by enforcing **password policies, MFA, and session timeouts**.
3. **Encrypt all network communications** using **TLS (HTTPS/SSL VPN)**.
4. **Conduct employee security awareness training**.
5. **Deploy SIEM and IDS solutions** for **real-time attack detection**.
6. **Regular vulnerability assessments** and **automated patching**.

---

## **References**
- [CMMC Self-Assessment Guide](https://dodcio.defense.gov/Portals/0/Documents/CMMC/AG_Level1_V2.0_FinalDraft_20211210_508.pdf)
- [NIST SP 800-171 Security Requirements](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)

---



