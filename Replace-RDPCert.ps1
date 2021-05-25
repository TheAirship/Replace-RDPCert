<#

.SYNOPSIS
Replace the TLS certificate used by the Windows operating system for Remote Desktop Services with a CA-signed cert.

.DESCRIPTION
Replaces TLS certificates used by the target machine for Remote Desktop Services with a certificate that is
signed by an Active Directory Certificate Services (ADCS) Certificate Authority (CA). The CA must be reachable 
by the target computer, and a relevant certificate template must be available for enrollment. Only two parameters 
are required: the name of the CA and the name of the certificate template. A properly-formatted, custom 
RequestPolicy.inf file may be passed using an optional parameter.

.PARAMETER CAName
The full name of the CA that will fulfill the certificate request. The FULL CA name is required, which is usually in the
following format: [CA_Server_DNS_Name]\[CA_Name]. An example of a full CA name might be 'subCA.example.local\ExampleSubCA'.
Passing the server's DNS name or the CA name alone will likely cause Replace-RDPCert to throw an error.

.PARAMETER CertTemplate
The name of the certificate template that will be used for the creation of the RDP certificate. The common name of the 
certificate template, not the display name, is required. 

.PARAMETER ReqFile
A specific RequestPolicy.inf file created by the user. Will replace the boilerplate RequestPolicy.inf file when passed to 
Replace-RDPCert.

.PARAMETER StagingDir
The staging directory used to prepare the certificate request files. Replace-RDSCert defaults to the user's Desktop, but
another directory may be designated (e.g., if a service account is running the script).

.PARAMETER CertFile
A CA-signed certificate file to be imported into the relevant certificate stores and used by the system's Remote Desktop
Services.

.PARAMETER CertThumb
The thumbprint of a certificate that has already been imported into the system's Personal store and will be used by
the system's Remote Desktop Services.

.PARAMETER ReqID
The request ID for a certificate request that has been taken under submission by an issuing CA. The request ID can be
passed to the script after the requested certificate has been issued. The certificate will be retrieved, imported
and applied.

.EXAMPLE
Replace-RDPCert -CertTemplate RDPCert

Description
--------------------------------
Requests a certificate with the 'RDPCert' template from the system-configured issuing CA using a boilerplate RequestPolicy.inf file, 
applies it to Remote Desktop Services on the local machine, and cleans up all files created in the process.

.EXAMPLE
Replace-RDPCert -CAName subCA.example.local\ExampleSubCA -CertTemplate RDPCert -ReqFile C:\Users\example\Desktop\RequestPolicy.inf

Description
--------------------------------
Requests a certificate with the 'RDPCert' template from a user-designated issuing CA using a custom-made RequestPolicy.inf file, 
applies it to Remote Desktop Services on the local machine, and cleans up all files created in the process.

.EXAMPLE
Replace-RDPCert -CertFile C:\Users\example\Desktop\NewRDPCert.cer

Description
--------------------------------
Imports a CA-signed certificate that has been manually retrieved from a CA into a system's relevant certificate stores, then
applies it to Remote Desktop Services. This command should be used when CA Manager approval is required to issue a certificate.

.EXAMPLE
Replace-RDPCert -CertThumb "f06845797861f26d59652ef79ec49d3aac2eb42f"

Description
--------------------------------
Applies an existing, CA-signed certificate from a system's Personal certificate store to Remote Desktop Services by referencing 
the certificate's Thumbprint.

.EXAMPLE
Replace-RDPCert -ReqID 110

Description
--------------------------------
Retrieves a certificate from an issuing CA when the certificate type requires CA Manager approval. This parameter should be
used only after the pending certificate request has been approved.

.NOTES
FunctionName : Replace-RDPCert
Author       : Craig Jackson
Version      : 1.0 (5/24/2021)
License      : Apache 2.0
More Info    : https://www.github.com/theairship/replace-rdpcert

#>

#Requires -RunAsAdministrator

param (
    [Parameter(Mandatory=$False)]
    [string[]]
    $CertTemplate,

    [Parameter(Mandatory=$False)]
    [string[]]
    $CAName,

    [Parameter(Mandatory=$False)]
    [string[]]
    $ReqFile,

    [Parameter(Mandatory=$False)]
    [string[]]
    $StagingDir,

    [Parameter(Mandatory=$False)]
    [string[]]
    $CertFile,

    [Parameter(Mandatory=$False)]
    [string[]]
    $CertThumb,

    [Parameter(Mandatory=$False)]
    [string[]]
    $ReqID

)

########################
### Script Functions ###
########################

function Invoke-Failure ($succCount, $failCount, $failStr) {

    ### Throws error string and exits script on error ###

    Write-Host " - " -NoNewline
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "         [ERROR] $failStr."
    Write-Host "`n[RESULT] Exiting with $succCount success(es), $failCount failure(s)."
    Write-Host "`r"

    Exit

}

function Get-IssuingCA {

    ### If the user hasn't provided a specific issuing CA, attempt to pull it via certutil ###

    Write-Host "[STATUS] No issuing CA provided, attempting to determine from current settings" -NoNewline

    Try {

        $caName = (certutil | Select-String "Config").ToString().Split(":")[1].Trim().Replace("`"","")

        If ($caName -eq "") {

            $global:failCount++
            $failStr = "Failed to determine issuing CA"
            Invoke-Failure $global:succCount $global:failCount $failStr
             
        }

        Else {

            Write-Host " - " -NoNewline
            Write-Host "SUCCESS" -ForegroundColor Green
            Write-Host "         [INFO] The issuing CA for this request will be: $caName"
            $global:succCount++

            return $caName

        }

    }

    Catch {

        $global:failCount++
        $failStr = "Failed to determine issuing CA"
        Invoke-Failure $global:succCount $global:failCount $failStr     

    }

}

function Check-IssuingCA ($caName) {

    ### Checks to ensure that the ADCS service is reachable on the CA ###

    Write-Host "[STATUS] Confirming that the ADCS service is reachable on the CA" -NoNewline

    $caCheck = certutil -ping -config "sca.theairship.local\airshipsubca"

    If ($caCheck -match "interface is alive") {

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        $global:succCount++

    }

    Else {

        $global:failCount++
        $failStr = "ADCS service could not be reached on the target CA. Please confirm that you've used the full config name of the CA and try again."
        Invoke-Failure $global:succCount $global:failCount $failStr 

    }

}

function Check-Template ($crtTemplate, $caName) {

    ### Checks to ensure that the certificate template passed by the user is valid for the selected CA ###

    Write-Host "[STATUS] Confirming that the requested certificate template exists on the issuing CA" -NoNewline

    $allTemps = certutil -catemplates -mt -config $caName

    If ($allTemps -match $crtTemplate) {

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        $global:succCount++

    }

    Else {

        $global:failCount++
        $failStr = "The requested certificate template could not be located on the configured CA. Please confirm that the certificate template name is spelled
                 correctly and try again. You can also choose a different issuing CA using the -CAname parameter"
        Invoke-Failure $global:succCount $global:failCount $failStr  

    }

}

function Get-CurrentCert {

    ### Get information on the current RDP server cert ###

    Write-Host "[STATUS] Attempting to gather information on current RDP server cert" -NoNewline

    Try {

        $TSCurrentSet = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
        $TSCurrentCert = $TSCurrentSet | select -ExpandProperty SSLCertificateSHA1Hash

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        Write-Host "         [INFO] The Thumbprint for the current RDP server cert is $TSCurrentCert"
        $global:succCount++

        ### Check to see if there are multiple certs in the Remote Desktop store ###

        If ((Get-ChildItem 'Cert:\LocalMachine\Remote Desktop').count -gt 1) {

            Write-Host "         [WARN] There are multiple certificates in the Remote Desktop Certificate store on this system. Only the certificate with 
                thumbprint ending in" $TSCurrentCert.substring($TSCurrentCert.length - 4,4) "will be removed by this script."

        }

        return $TSCurrentCert

    }

    Catch {

        $global:failCount++
        $failStr = "Failed to get current ceritifcate from RDP store"
        Invoke-Failure $global:succCount $global:failCount $failStr

    }

}

function Get-RequestFile ($stgDir, $reqFile) {

### Confirm whether request info file was passed; if not, create it ###

    if ($reqFile -eq $null) {

        ### Create ReqFile in designated staging directory, user's desktop if one wasn't defined ###

        Write-Host "[STATUS] Attempting to create generic Cert Request file in designated staging directory" -NoNewline
    
        Try {

            $reqFile = "$stgDir\RequestPolicy.inf"
            $hostName = [system.net.dns]::GetHostByName($compName).HostName
            $ipAddr = (Test-Connection -ComputerName $compName -Count 1).IPV4Address.IPAddressToString

            If ((test-path -Path $reqFile) -eq $True) {

                $global:failCount++
                $failStr = "A RequestPolicy.inf file was already found at the path provided. To prevent accidental modification,
                 it will not be overwritten. If this file is no longer needed, delete it and re-run this script.
                 Otherwise, pass the file to the script using the -ReqFile parameter"
                Invoke-Failure $global:succCount $global:failCount $failStr 

            }

            "[Version]`r`nSignature = `"`$Windows NT`$`"`r`n[NewRequest]" | Out-File -FilePath $reqFile -NoClobber 
            "Subject = `"CN=$hostName`"`r`nFriendlyName = `"$compName-RDP`"" | Out-File -FilePath $reqFile -Append
            "Exportable = False`r`nKeyLength = 2048`r`nKeySpec = 1`r`nKeyUsage = 0xA0" | Out-File -FilePath $reqFile -Append
            "MachineKeySet = True`r`nRequestType = PKCS10`r`nHashAlgorithm = SHA256" | Out-File -FilePath $reqFile -Append
            #"ProviderName = `"Microsoft RSA SChannel Cryptographic Provider`"`r`n" | Out-File -FilePath $reqFile -Append
            "[EnhancedKeyUsageExtension]`r`nOID = 1.3.6.1.5.5.7.3.1`r`nOID = 1.3.6.1.5.5.7.3.2" | Out-File -FilePath $reqFile -Append
            "[Extensions]`r`n2.5.29.17 = `"{text}`"`r`n_continue_ = `"dns=$hostName&`"" | Out-File -FilePath $reqFile -Append
            "_continue_ = `"dns=$compName&`"`r`n_continue_ = `"ipaddress=$ipAddr&`"" | Out-File -FilePath $reqFile -Append
            "[RequestAttributes]`r`nCertificateTemplate = $CertTemplate" | Out-File -FilePath $reqFile -Append

            Write-Host " - " -NoNewline
            Write-Host "SUCCESS" -ForegroundColor Green
            $global:succCount++

            return $reqFile

        }

        Catch {

            $global:failCount++
            $failStr = "Failed to write RequestPolicy.inf file to staging directory"
            Invoke-Failure $global:succCount $global:failCount $failStr  

        }

    }

    Else {

        ### Be sure the user-designated RequestPolicy.inf file exists ###

        Write-Host "[STATUS] Confirming user-provided RequestPolicy.inf file exists" -NoNewline  

        If ((Test-Path -Path $reqFile) -eq $True) {

            Write-Host " - " -NoNewline
            Write-Host "SUCCESS" -ForegroundColor Green
            $global:succCount++

            return $reqFile   
                      
        }
    
        Else {

            $global:failCount++
            $failStr = "Failed to open user-designated RequestPolicy.inf file"
            Invoke-Failure $global:succCount $global:failCount $failStr

        } 

    }

}

function Create-CSR ($stgDir, $compName, $reqFile) {

    ### Attempt to create a CSR from the RequestPolicy.inf file ###

    Write-Host "[STATUS] Attempting to create a CSR from the RequestPolicy.inf file" -NoNewline

    Try {

        $csrFile = "$stgDir\$compName-RDP.csr"

        certreq -new -q -machine $reqFile $csrFile | Out-Null

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        $global:succCount++

        return $csrFile

    }

    Catch {

        $global:failCount++
        $failStr = "Failed to create CSR file from the RequestPolicy.inf file"
        Invoke-Failure $global:succCount $global:failCount $failStr 

    }

}

function Get-RDPCert ($stgDir, $caName, $compName, $csrFile) {

    ### Attempt to request new cert from issuing CA ###

    Write-Host "[STATUS] Attempting to request new certificate from issuing CA" -NoNewline

    Try {

        $crtFile = "$stgDir\$compName-RDP.cer"
    
        $caResp = certreq -submit -f -config $caName $csrFile $crtFile # | Out-Null

        If ($caResp -imatch "retrieved") {

            Write-Host " - " -NoNewline
            Write-Host "SUCCESS" -ForegroundColor Green
            $global:succCount++

            $newCert = Import-RDPCert $crtFile
            return $newCert

        }

        ElseIf ($caResp -imatch "pending") {

            $global:failCount++
            $reqID = $caResp[0].split(":")[1].trim()
            $failStr = "The certificate request submission was successful, but the CA responded with a 'pending' status. The selected certificate template  
                 may be configured to require CA Manager approval. Either reconfigure the certificate template and try again, or approve the
                 request, then...
                    -Download the certificate manually and pass it to this script for import using the -CertFile parameter, or
                    -Re-run the script and use the -ReqID parameter with the Request ID $reqID"
            Invoke-Failure $global:succCount $global:failCount $failStr            

        }

        Else {

            $global:failCount++
            $failStr = "The CA refused to issue a certificate for this request"
            Invoke-Failure $global:succCount $global:failCount $failStr  

        }

    }

    Catch {

        $global:failCount++
        $failStr = "Failed to submit CSR to issuing CA"
        Invoke-Failure $global:succCount $global:failCount $failStr 

    }

}

function Retrieve-IssuedCert ($ReqID, $stgDir, $compName, $caName) {

    ### Attempt to retrieve an isused cert from the CA in preparation for import ###

    Write-Host "[STATUS] Attempting to retrieve issued cert from CA" -NoNewline  

    $newCert = "$stgDir\$compName-RDP.cer"      

    Try {

        certreq -retrieve -f -config $caName $ReqID $newCert | Out-Null

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        $global:succCount++

        return $newCert

    }

    Catch {

        $global:failCount++
        $failStr = "Failed to retrieve the issued cert from the CA. Please check your Request ID and CA name and try again"
        Invoke-Failure $global:succCount $global:failCount $failStr

    }

}

function Import-RDPCert ($crtFile) {

    ### Attempt to add the new certificate to the RDP certificate store ###

    Write-Host "[STATUS] Attempting to import new certificate to the Personal and RDP certificate stores" -NoNewline

    $TSNewCert = (certutil $crtFile | select-string "Cert Hash\(sha1\)").ToString().split(":")[1].trim()

    Try {

        Import-Certificate -FilePath $crtFile -CertStoreLocation "Cert:\LocalMachine\My" | Out-Null
        Import-Certificate -FilePath $crtFile -CertStoreLocation "Cert:\LocalMachine\Remote Desktop" | Out-Null

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        $global:succCount++

    }

    Catch {

        Try {

            certreq -accept $crtFile | Out-Null
            certutil -addstore -machine -f "Remote Desktop" $crtFile | Out-Null

            Write-Host " - " -NoNewline
            Write-Host "SUCCESS" -ForegroundColor Green
            $global:succCount++

        }

        Catch {

            $global:failCount++
            $failStr = "Failed to import certificate to Personal and Remote Desktop certificate stores. This sometimes happens when
                     the system does not have a private key associated with the certificate. Check to be sure the system has a 
                     private key associated with the certificate you're importing and try again"
            Invoke-Failure $global:succCount $global:failCount $failStr 

        }

    }

    Write-Host "         [INFO] The Thumbprint for the new RDP server cert is $TSNewCert"
    return $TSNewCert

}

function Apply-RDPCert ($newCert) {

    ### Attempt to set new certificate as primary for RDP ###

    Write-Host "[STATUS] Attempting to set new certificate as primary for RDP" -NoNewline

    If ((Get-ChildItem "Cert:\LocalMachine\My\$newCert" -ErrorAction SilentlyContinue) -eq $null) {

        $global:failCount++
        $failStr = "A certificate with that thumbprint couldn't be found in this system's Personal certificate store. 
                 Please confirm that you're using the correct thumbprint and that the related cert has already been imported
                 into the local machine's Personal certificate store."
        Invoke-Failure $global:succCount $global:failCount $failStr        

    }

    Try {

        #wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralSetting Set SSLCertificateSHA1Hash=$TSNewCert | Out-Null

        $tsPath = (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
        Set-WmiInstance -Path $tsPath -Arguments @{SSLCertificateSHA1Hash=$newCert} | Out-Null

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        $global:succCount++

    }

    Catch {

        $global:failCount++
        $failStr = "Failed to set new cert as primary for Remote Desktop Services"
        Invoke-Failure $global:succCount $global:failCount $failStr 

    }

}

function Verify-RDPCert ($newCert) {

    ### Verify that the new cert is now being used for RDP connections ###

    Write-Host "[STATUS] Verifying RDP cert replacement" -NoNewline

    Try {

        $result = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'" -ErrorAction SilentlyContinue

        If (($result | select -ExpandProperty SSLCertificateSHA1Hash) -eq $newCert) {

            Write-Host " - " -NoNewline
            Write-Host "SUCCESS" -ForegroundColor Green
            $global:succCount++

        }

        Else {

            Write-Host " - " -NoNewline
            Write-Host "FAILED" -ForegroundColor Red
            $global:failCount++

        }

    }

    Catch {

        $global:failCount++
        $failStr = "Failed to verify Remote Desktop certificate replacement"
        Invoke-Failure $global:succCount $global:failCount $failStr 

    }

}

function Remove-OldCert ($currCrt) { 

    ### Remove the old cert from the RDP store ###

    Write-Host "[STATUS] Attempting to remove old self-signed cert from RDP store" -NoNewline -ErrorAction Stop

    Try {

        Get-ChildItem "Cert:\LocalMachine\Remote Desktop\$currCrt" | Remove-Item

            Write-Host " - " -NoNewline
            Write-Host "SUCCESS" -ForegroundColor Green
            Write-Host "         [WARN] Since a machine's self-signed cert may be used for multiple services, this function will only remove the old 
                certificate from the Remote Desktop store to prevent issues with other services. The certificate will need to be 
                manually removed from the system's Personal store, if desired."
            $global:succCount++
        
    }

    Catch {

        $global:failCount++
        $failStr = "Failed to remove old self-signed cert from RDP store"
        Invoke-Failure $global:succCount $global:failCount $failStr 

    }

}

function Remove-ReqFiles ($stgDir, $compName, $delFile) {

    ### Clean up files created during this process ###

    Write-Host "[STATUS] Attempting to clean up automated cert request files" -NoNewline

    Try {

        If ((Test-Path -Path "$stgDir\RequestPolicy.inf") -eq $True) {
            If ($delFile = $True) {
                Remove-Item "$stgDir\RequestPolicy.inf"
            }
        }

        If ((Test-Path -Path "$stgDir\$compName-RDP.csr") -eq $True) {
            Remove-Item "$stgDir\$compName-RDP.csr"
        }

        If ((Test-Path -Path "$stgDir\$compName-RDP.rsp") -eq $True) {
            Remove-Item "$stgDir\$compName-RDP.rsp"
        }

        If ((Test-Path -Path "$stgDir\$compName-RDP.cer") -eq $True) {
            Remove-Item "$stgDir\$compName-RDP.cer"
        }

        Write-Host " - " -NoNewline
        Write-Host "SUCCESS" -ForegroundColor Green
        $global:succCount++
        
    }

    Catch {

        $global:failCount++
        $failStr = "Failed to clean up cert request files created by Replace-RDPCert"
        Invoke-Failure $global:succCount $global:failCount $failStr 

    }

}

############
### Main ###
############

### Set up preferences and variables ###

$ErrorActionPreference = "Stop"
$compName = $env:COMPUTERNAME
$global:succCount = 0
$global:failCount = 0
$currVersion = "1.0.0"
$startTime = (Get-Date).Second

If ($StagingDir -eq $null) {

    $StagingDir = [Environment]::GetFolderPath("Desktop")

}

If ($ReqFile -eq $null) {

    $delFile = $True

}

Else {

    $delFile = $False
    
}

### Print a pretty banner ###

Write-Host "`r"
Write-Host ("*" * 70)
Write-Host "* Replace-RDPCert $(" " * 50) *"
Write-Host "* Version: $currVersion $(" " * (70 - (14 + $currVersion.length))) *"
Write-Host "* More Info: https://www.github.com/theaiarship/replace-rdpcert      *"
Write-Host ("*" * 70)
Write-Host "`r"

### Determine user configuration and execute ###

If ($CertTemplate -ne $null) {

    ### User wants to begin from scratch, create the necessary certificate request,
    ### retrieve and import the cert, and apply it to Remote Desktop Services.

    If ($CAName -eq $null) {
    
        $CAName = Get-IssuingCA

    }

    Else {

        Write-Host "The issuing CA selected for this request will be: $CAName"

    }

    Check-IssuingCA -caName $CAName

    Check-Template -crtTemplate $CertTemplate -caName $CAName

    $currCrt = Get-CurrentCert

    $reqFile = Get-RequestFile -stgDir $StagingDir -reqFile $ReqFile

    $csrFile = Create-CSR -stgDir $StagingDir -compName $compName -reqFile $ReqFile

    $newCert = Get-RDPCert -stgDir $StagingDir -caName $CAName -compName $compName -csrFile $csrFile

    Apply-RDPCert $newCert

    Verify-RDPCert $newCert

    Remove-OldCert $currCrt

    Remove-ReqFiles -stgDir $StagingDir -compName $compName -delFile $delFile

}

Elseif ($ReqID -ne $null) {

    ### User wants to retrive and issued certificate from a CA by its Request ID
    ### import it into the necessary certificate stores and set it for use by RDP.

    If ($CAName -eq $null) {
    
        $CAName = Get-IssuingCA

    }

    Else {

        Write-Host "The issuing CA selected for this request will be: $CAName"

    }

    $currCrt = Get-CurrentCert

    $CertFile = Retrieve-IssuedCert -ReqID $ReqID -stgDir $StagingDir -compName $compName -caName $CAName
    
    $newCert = Import-RDPCert $CertFile

    Apply-RDPCert $newCert

    Verify-RDPCert $newCert

    Remove-OldCert $currCrt

    Remove-ReqFiles -stgDir $StagingDir -compName $compName -delFile $delFile

}

Elseif ($CertFile -ne $null) {

    ### User wants to import a certificate that has been manually retrieved
    ### from the issuing CA into the necessary certificate stores and set it 
    ### for use by RDP.

    $currCrt = Get-CurrentCert

    $newCert = Import-RDPCert $CertFile

    Apply-RDPCert $newCert

    Verify-RDPCert $newCert

    Remove-OldCert $currCrt

    Remove-ReqFiles -stgDir $StagingDir -compName $compName -delFile $delFile

}

Elseif ($CertThumb -ne $null) {

    ### User wants to apply a certificate that has already been imported
    ### into the system's Personal store to Remote Desktop Services.

    $newCert = $CertThumb

    $currCrt = Get-CurrentCert

    Apply-RDPCert $newCert

    Verify-RDPCert $newCert

    Remove-OldCert $currCrt

}

Else {

    ### User has not passed any of the required arguments ###

    Write-Host "         [ERROR] You must provide either a certificate template name, a certificate file path, a certificate Thumbprint, or a certificate request ID." `
        "Please pass one of these required parameters and try again."

    Exit

}

### Close out with final status ###

$endTime = (Get-Date).Second
$runTime = $endTime - $startTime
Write-Host "`n[RESULT] Process complete! Exiting with $succCount success(es), $failCount failure(s) in $runTime second(s)."
Write-Host "`r" 