# Active-Directory-Project

### Overview

This project involved setting up an Active Directory environment across multiple VMs hosted on different cloud platforms (Azure and GCP) and a local VM. The objective was to establish a domain environment, collect telemetry data using Splunk, and test detection capabilities using Atomic Red Team (ART) simulations. The project aimed to enhance the understanding of Active Directory management, centralized log analysis, and security monitoring.

![Active-Directory-Final](https://github.com/user-attachments/assets/9ed25706-3531-49b9-bd4e-15fe0c93ef80)

### Project Components

1. **Splunk Installation**
    
    - Deployed a GCP Ubuntu VM to serve as the Splunk server.
        
    - Downloaded and installed Splunk Enterprise using the .deb package from the official website.
        
    - Configured Splunk to start as a service and set up the initial administrator account.
        
    - Enabled necessary firewall rules on GCP to allow inbound traffic on port 8000 (Splunk Web).
        
    - Verified Splunk access through the browser using the public IP and port 8000.
        
2. **Splunk Forwarder and Sysmon Installation**
    
    - Installed Splunk Universal Forwarder on Azure Windows Server and Windows 10 VM to forward logs to the Splunk server.
        
    - Downloaded Sysmon from the Sysinternals suite and configured it for enhanced logging.
        
    - Created and configured `inputs.conf` files to collect Application, Security, System, Sysmon and Powershell logs.
        
    - Set up the forwarder to send data to the Splunk server using the public IP and port 9997.
        
    - Validated the forwarder installation by checking the connection status in Splunk's Forwarder Management.
        
3. **Active Directory Setup**
    
    - Installed the AD Domain Services role on the Azure Windows Server VM to set it up as the Domain Controller.
        
    - Configured a new domain and created an organizational unit to manage users.
        
    - Created two user objects within the organizational unit for domain management.
        
    - Configured DNS settings on the Windows 10 VM to point to the AD server, allowing domain joining.
        
    - Successfully joined the Windows 10 VM to the AD domain and verified user account access.
        
4. **Brute-Force Attack Simulation**
    
    - Launched a brute-force attack using Kali Linux targeting the AD domain to test detection capabilities.
        
    - Monitored the generated logs on the Splunk dashboard to detect potential brute-force indicators.
        
5. **Atomic Red Team Setup and Attack Simulation**
    
    - Cloned the Atomic Red Team repository to Windows VMs and configured the environment.
        
    - Ran ART tests, including MITRE ATT&CK ID T1197, T1136.001 to simulate real-world attacks.
        
    - Monitored log generation on Splunk and verified successful detection and visualization of the attacks.
        
6. **Splunk Data Verification**
    
    - Connected to the Splunk server from both forwarder endpoints and validated data ingestion.
        
    - Examined hosts and sources on the Splunk dashboard to ensure the correct indexing of log data.
        
    - Checked the presence of Sysmon, Application, Security, System and Powershell logs in the configured Splunk index.
        

### Steps

1. Splunk installation and forwarder configuration

- Installing Splunk Enterprise on Ubuntu (using .deb package)

<pre>``` Bash
  
  ## Download the .deb package:
  wget -O splunk-9.2.1.deb 'https://download.splunk.com/products/splunk/releases/9.2.1/linux/splunk-9.2.1-91a427b462a9-linux-2.6-amd64.deb'

  ## Install the package:
  sudo dpkg -i splunk-9.2.1.deb

  ## Accept license and start Splunk:
  sudo /opt/splunk/bin/splunk start --accept-license

  ##Enable Splunk to start at boot:
  sudo /opt/splunk/bin/splunk enable boot-start
  
```</pre>  

- Installing Splunk Universal Forwarder on Windows 10

  Download the Universal Forwarder Installer:
  Go to Splunk Downloads - Forwarder, select Windows, and download the .msi installer.
  
  Install with GUI (Default):
  Double-click the .msi file and follow the wizard. Provide the Splunk server IP and receiving port (usually 9997).
  

  - Configuration file for Splunk Forwarder inputs.
	Shows the configured `inputs.conf` that defines which log sources are being collected from Windows machine.
	
	<img width="1440" alt="Final-inputs-conf" src="https://github.com/user-attachments/assets/8a2d4bc3-98b3-4a89-b43c-3eddc7b6f5f8" />


  ### Active Directory setup on Windows Server

- Promoted the Azure Windows Server to a Domain Controller with AD DS role.
- Created a domain (e.g., `dark.local`) and structured Organizational Units (OUs).
- Created user objects and assigned them to respective OUs.
- Set DNS on Windows 10 VM to point to the DC and successfully joined it to the domain.
- Verified user login using domain credentials.
	
	-> Creating user accounts in Active Directory.
	Demonstrates the creation of domain user objects within Active Directory Users and Computers (ADUC).
	
	<img width="1440" alt="Create-user-objects-AD" src="https://github.com/user-attachments/assets/823de772-02eb-49b7-a5aa-e900dc33edab" />

	
	-> Initiating the creation of an Organizational Unit (OU).
	Captures the step of organizing domain resources by department or role.
	
	<img width="1440" alt="Creating-Organizational-Unit" src="https://github.com/user-attachments/assets/8bf748c3-7eeb-47d2-8dfd-1c4d74b4e5ae" />

	
	-> _Saving the IT Organizational Unit._  
	Confirms the creation of a dedicated OU for IT department users or resources.
	
	<img width="1440" alt="Saving-Organizational-unit-IT" src="https://github.com/user-attachments/assets/abcf8e93-64b0-4ffc-b070-a05840607181" />

	
	-> _Saving the HR Organizational Unit._  
	Confirms the creation of a dedicated OU for HR department users or resources.
	
	<img width="1440" alt="New-Organizational-unit-HR" src="https://github.com/user-attachments/assets/2f7e10d9-7ae3-45ac-b777-fb585f132239" />

	
	-> _Adding a new user inside IT OU._  
	Shows how users are assigned to a specific OU during creation.
	
	<img width="1440" alt="Create-new-user-in-OU" src="https://github.com/user-attachments/assets/bf02bde2-3648-4c76-bd0d-85f5f8d507e4" />

	
	-> _Details of the user “Jenny” under IT OU._  
	Covers general info and account settings configured for the user.
	
	<img width="1440" alt="User-Jenny-details-1" src="https://github.com/user-attachments/assets/5c94278f-c213-4747-98e9-d4f5caaeb943" />
	
	<img width="1440" alt="User-Jenny-details-2" src="https://github.com/user-attachments/assets/95056041-ec62-4de6-afc5-7fcb8bdd48ee" />

	
	-> _User “Ken” creation inside the HR OU._  
	Highlights the configuration for an HR user, maintaining organizational separation.
	
	<img width="1440" alt="Create-new-user-HR-OU-Ken" src="https://github.com/user-attachments/assets/59c5d576-d321-4aa9-8200-c5103b237630" />
	
	<img width="1440" alt="User-details-Ken-2" src="https://github.com/user-attachments/assets/649af2a4-e907-491e-bf79-fe2c3c6a2d0c" />
	

  ### Windows 10 domain connection

  - Joined the Windows 10 VM (`Target-PC`) to the `dark.local` domain.
  - Logged in with domain users to validate successful domain connection.
	
	-> _Joining the Windows 10 machine to the AD domain._  
	Verifies that the endpoint was successfully connected to the AD environment.
	
	<img width="1440" alt="Add-Target-PC-To-AD-Domain" src="https://github.com/user-attachments/assets/ccb13fd8-c2a4-47cc-8476-9c4c9f4bd8bc" />

	
	-> _Adding a domain user (jsmith) on Windows 10._  
	Demonstrates the login configuration with Active Directory credentials.
	
	<img width="1440" alt="Add-user-AD-jsmith" src="https://github.com/user-attachments/assets/2476f935-ece5-42bd-a74d-bbf514951b7e" />

	
	-> _Domain user successfully logged in._  
	Confirms a working trust between the Windows 10 machine and the domain controller.
	
	<img width="1440" alt="User-added-target-PC-jsmith" src="https://github.com/user-attachments/assets/ac145d29-c22e-4a98-bd2b-9956b3aa07a7" />

		
  ### Brute-force attack simulation from Kali Linux
  
- Used Kali Linux to launch a brute-force attack on the domain login interface.
- Captured and analyzed failed login attempts in Splunk.
	
	-> _Simulated brute-force attack targeting user ksmith._  
	Conducting RDP Bruteforce attack using hydra on Windows10 IP.
	
    <img width="1440" alt="Brute-force-attack-domain-user-ksmith" src="https://github.com/user-attachments/assets/96d89733-4d46-451f-9498-dafcdabdd02f" />

    
- Telemetry data visualization in Splunk
	
	->Detecting bruteforce successful login.
	
    <img width="1440" alt="Detecting-bruteforce-splunk" src="https://github.com/user-attachments/assets/e7e585a5-6876-4c07-94c8-cd3bd9d3178a" />


  ### ART setup and execution of Atomic Tests

- Cloned Atomic Red Team repo on Windows VM.
- Installed dependencies and ran tests for various MITRE ATT&CK techniques (e.g., T1059.001, T1021.002).
- Captured telemetry through Sysmon and validated detections in Splunk.
	
	-> _Bypassing PowerShell execution policy to install ART._  
	For preparing the environment to execute unsigned scripts.
	
	<img width="853" alt="Set-Bypass-ExecutionPolicy-ART-Install" src="https://github.com/user-attachments/assets/69735b1e-6018-4707-9620-0f1bbfb8feea" />

	
	-> _Atomic Red Team installation process._  
	Screenshot showing successful module setup.
	
    <img width="1440" alt="Installing-Atomic-Red-Team" src="https://github.com/user-attachments/assets/60c1b56b-796e-48db-bd29-4f49960f8695" />

	
	-> _Execution of BITSAdmin-related TTPs._  
	Shows commands that simulate malicious use of Background Intelligent Transfer Service (T1197).
	
	<img width="1440" alt="Bitsadmin" src="https://github.com/user-attachments/assets/1a0f27b7-6b53-445c-b6de-b929b2c2fd37" />

	
	-> _Creation of a local user via ART test._  
	Reflects account creation techniques typically associated with persistence or privilege escalation (T1136.001).
	
	<img width="1440" alt="NewLocalUser" src="https://github.com/user-attachments/assets/5416e7c7-9e9f-43b9-8119-8195d28d65b8" />

	
- ### Detection of simulated attacks on Splunk

   - Verified host connectivity and log ingestion.
   - Used Splunk queries to identify successful detections:
    
	-> _Splunk detection of BITSAdmin command activity._  
	Validates telemetry and detection logic for simulated network or download abuse.
	
    <img width="1440" alt="Bitsadmin-detection" src="https://github.com/user-attachments/assets/c7cb9f3b-f766-4957-940b-b55c09eb9b6a" />

	
	-> _Detection of new local user creation in logs._  
	 T1197 detection of new Windows admin user creation via .NET.
	
	<img width="1440" alt="NewLocalUser-Detection" src="https://github.com/user-attachments/assets/5b95ec50-d45b-472e-8607-e0ac85d07e2e" />

	
	-> _Detection of lateral movement using PsExec._  
	Confirms detection of remote execution techniques (T1021.002) in the Splunk dashboard.
	
	<img width="1440" alt="T1021-Detection" src="https://github.com/user-attachments/assets/df874aaa-d219-4f99-ab2c-c1db50d33c3c" />

	
### Conclusion

This project successfully demonstrated the setup of a functional Active Directory environment with multi-cloud integration, log collection using Splunk, and threat detection via Atomic Red Team simulations. It provided hands-on experience in:

- Configuring AD Domain Services
    
- Ingesting and visualizing telemetry in Splunk
    
- Simulating and detecting MITRE ATT&CK techniques
    
- Handling cross-platform infrastructure for security monitoring
    
