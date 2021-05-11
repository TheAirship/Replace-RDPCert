# EZ-RDP-Cert-Changer

*Did you know?* Simply replacing the certificate in Windows' Remote Desktop certificate store *won't* actually change the certificate that the system uses to negotiate an encrypted RDP connection. It's necessary to use PowerShell or WMIC commands to reconfigure WMI to use the replacement certificate.

By default, Windows systems create a self-signed certificate for use by Remote Desktop Services when it is enabled. This is the self-signed certificate that causes the ubiquitous "The identity of the remote computer cannot be verified errors" and appears constantly on vulnerability scans with the findings like "Untrusted certificate detected on TCP 3389" and "Remote Desktop using self-signed certificate".
