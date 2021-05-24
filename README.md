# Replace-RDPCert

***Did you know?*** By default, Windows systems create a self-signed certificate for use by Remote Desktop Services when it is enabled. This is the same self-signed certificate that causes the ubiquitous "The identity of the remote computer cannot be verified errors" and appears constantly on vulnerability scans with findings like "Untrusted certificate detected on TCP 3389" and "Remote Desktop using self-signed certificate". But simply replacing the certificate in Windows' Remote Desktop certificate store *won't* actually change the certificate that the system uses to negotiate an encrypted RDP connection. It's necessary to use PowerShell or WMIC commands to reconfigure WMI to use the replacement certificate.

Replace-RDPCert is a PowerShell cmdlet that simplifies the process of replacing the certificate used by Remote Desktop Services on a Windows system. Unlike applying the Remote Desktop cert through GPO, Replace-RDPCert allows for granular customization of the issued cert through creation or use of a RequestPolicy.inf file. Specifically, this means that SANs can be added to the cert.

## Prerequisites

There are only a few recommended prerequisites for using Replace-RDPCert efficiently:

- PowerShell v4.0+ is required, and the PowerShell session must be run as a user with local administrator privileges on the target system
- Active Directory Certificate Services (ADCS) should be configured for the target system's domain, and an authorized issuing CA should be reachable
- A certificate template with configs appropriate to Remote Desktop Services must be available for issue by the issuing CA

To clarify, ADCS isn't strictly required. It should be possible to use a cert issued by a third-party CA as long as the target system has a private key associated with the cert. It would also be a good idea for the issuing CA and / or the issuing CA's root CA to be trusted by the target system. See use scenarios #2 and #4 below for reference.

There are many resources to guide the creation of a proper certificate template for RDS, so that won't be covered here. Replace-RDPCert will work most efficiently with a certificate template that does *not* require CA Manager approval for issuance. Since issuing certain certs without CA manager approval may violate some organizations' security policy, the script is also able to retrieve and install a certificate after CA manager approval. See use scenario #3 below.

## Use Cases & Command Examples

There are 4 scenarios that Replace-RDPCert can help with:

### Scenario 1 - Soup to Nuts

The true intent of Replace-RDPCert is to manage the RDP cert replacement process from creation of the RequestPolicy.inf file, to the creation of the CSR file, submission of the request, retrieval and import of the issued certificate, and replacement of the RDP cert in WMI. When the ADCS environment is configured to allow this process, only the common name of the RDP certificate template needs to be passed to the script. The common name is required; the script will fail if the certificate template's display name is used.

```PowerShell
PS> .\Replace-RDPCert.ps1 -CertTemplate [RDP_Certificate_Template_Name]
```

In some cases, a user may want to designate a specific issuing CA instead of allowing the script to use the one configured as primary for the target computer. In this case, the full CA config name is required. The full config name is usually [CA_Server_DNS_Name]\[CA_Name] (e.g., "subCA.theairship.local\AirshipIssuingCA").

```PowerShell
PS> .\Replace-RDPCert.ps1 -CertTemplate [RDP_Certificate_Template_Name] -CAName [Full_CA_Name]
```

It's also possible to use a custom RequestPolicy.inf file instead of the boilerplate file that the script creates by default.

```PowerShell
PS> .\Replace-RDPCert.ps1 -CertTemplate [RDP_Certificate_Template_Name] -ReqFile [Full_Path_to_File]
```

### Scenario 2 - Retrieve, Import & Apply Cert

Some organizations may require CA manager approval for a certificate request to be issued, so the script will not be able to retrieve it immediately. In these cases, the script will notify he user what Request ID is associated with the certificate submission. Once confirmation is received that the certificate is issued, the following command can be used with the Request ID to retrieve, import, and apply the cert.

```PowerShell
PS> .\Replace-RDPCert.ps1 -ReqID [Request_ID_Received_From_Script]
```

### Scenario 3 - Import & Apply Cert

If an approved certificate was manually delivered to the user to be applied, it can be passed to the script for import and configuration using the -CertFile parameter, as shown below.

```PowerShell
PS> .\Replace-RDPCert.ps1 -CertFile [Path_to_Certificate_File]
```

### Scenario #4 - Apply Existing (Previously Imported) Cert

If a certificate appropriate for RDP already exists in the Personal store on the target system, it can be applied as the Remote Desktop Services using the -CertThumb parameter.

```PowerShell
PS> .\Replace-RDPCert.ps1 -CertThumb [Certificate_Thumbprint]
```

## References

Replace-RDPCert is an aggregation of research that resulted in a script. In particular, the following articles were referenced:

- https://aventistech.com/2019/08/08/replace-rdp-default-self-sign-certificate/
- 

## About / License

