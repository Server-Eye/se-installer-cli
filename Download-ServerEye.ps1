#
# Download_ServerEye.ps1
#

new-module -name Downloader -scriptblock {


  function Download-SEInstallationFiles {

		$SE_baseDownloadUrl = "https://occ.server-eye.de/download"
		$SE_cloudIdentifier = "se"
		$SE_vendor = "Vendor.ServerEye"
		
	
		Write-Host "  getting current Server-Eye version... " -NoNewLine
		$wc = new-object system.net.webclient
		$curVersion = $wc.DownloadString("$SE_baseDownloadUrl/$SE_cloudIdentifier/currentVersion")
		Write-Host "done" -ForegroundColor Green

		Write-Host "  current version: " -NoNewLine
		Write-Host "$curVersion" -ForegroundColor DarkGray
	
		Write-Host "  downloading ServerEye.Vendor... " -NoNewline
		Download-SEFile "$SE_baseDownloadUrl/vendor/$SE_vendor/Vendor.msi"  "$PWD/Vendor.msi"
		Write-Host "done" -ForegroundColor Green
	
		Write-Host "  downloading ServerEye.Core... " -NoNewline
		Download-SEFile "$SE_baseDownloadUrl/$curVersion/ServerEye.msi" "$PWD/ServerEye.msi"
		Write-Host "done" -ForegroundColor Green
	
	}

	function Download-SEFile {
		[CmdletBinding()]
		Param (
			[string]
			$Url,
		
			[string]
			$TargetFile
		)
	
		try
		{
			$uri = New-Object "System.Uri" "$url"
			$request = [System.Net.HttpWebRequest]::Create($uri)
			$request.set_Timeout(15000) #15 second timeout
			$response = $request.GetResponse()
			$totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
			$responseStream = $response.GetResponseStream()
			$targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
			$buffer = new-object byte[] 10KB
			$count = $responseStream.Read($buffer, 0, $buffer.length)
			$downloadedBytes = $count
		
			while ($count -gt 0)
			{
				$targetStream.Write($buffer, 0, $count)
				$count = $responseStream.Read($buffer, 0, $buffer.length)
				$downloadedBytes = $downloadedBytes + $count
				Write-Progress -activity "Downloading file '$($url.split('/') | Select-Object -Last 1)'" -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $totalLength) * 100)
			}
		
			Write-Progress -activity "Finished downloading file '$($url.split('/') | Select-Object -Last 1)'" -Status "Done" -Completed
		
			$targetStream.Flush()
			$targetStream.Close()
			$targetStream.Dispose()
			$responseStream.Dispose()
		
		}
		catch
		{
		
			Write-Host -Message "Error downloading: $Url - Interrupting execution - $($_.Exception.Message)" -EventID 666 -EntryType Error
		}
	}

  Function Download-ServerEye() {

	$oldBack = $host.privatedata.ProgressBackgroundColor;
	$oldFore = $host.privatedata.ProgressForegroundColor;

	$host.privatedata.ProgressForegroundColor = "DarkGray";
	$host.privatedata.ProgressBackgroundColor = "Gray";

  	$AsciiArt_ServerEye = @"
  ___                          ___         
 / __| ___ _ ___ _____ _ _ ___| __|  _ ___ 
 \__ \/ -_) '_\ V / -_) '_|___| _| || / -_)
 |___/\___|_|  \_/\___|_|     |___\_, \___|
                                  |__/     
"@
	Write-Host $AsciiArt_ServerEye -ForegroundColor DarkYellow


    Download-SEInstallationFiles

	Write-Host "`nThe .msi files have been download." -ForegroundColor DarkGray

	$host.privatedata.ProgressForegroundColor = $oldFore;
	$host.privatedata.ProgressBackgroundColor = $oldBack;
  }

  set-alias download -value Download-ServerEye

  export-modulemember -function 'Download-ServerEye' -alias 'download'
}
# SIG # Begin signature block
# MIIazgYJKoZIhvcNAQcCoIIavzCCGrsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUW0Vl3W7tdSuygq0c6oKuzXe+
# YfqgghW+MIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
# BQUAMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQg
# TGFrZSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNV
# BAsTGGh0dHA6Ly93d3cudXNlcnRydXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJG
# aXJzdC1PYmplY3QwHhcNMTUxMjMxMDAwMDAwWhcNMTkwNzA5MTg0MDM2WjCBhDEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKjAoBgNVBAMT
# IUNPTU9ETyBTSEEtMSBUaW1lIFN0YW1waW5nIFNpZ25lcjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAOnpPd/XNwjJHjiyUlNCbSLxscQGBGue/YJ0UEN9
# xqC7H075AnEmse9D2IOMSPznD5d6muuc3qajDjscRBh1jnilF2n+SRik4rtcTv6O
# KlR6UPDV9syR55l51955lNeWM/4Og74iv2MWLKPdKBuvPavql9LxvwQQ5z1IRf0f
# aGXBf1mZacAiMQxibqdcZQEhsGPEIhgn7ub80gA9Ry6ouIZWXQTcExclbhzfRA8V
# zbfbpVd2Qm8AaIKZ0uPB3vCLlFdM7AiQIiHOIiuYDELmQpOUmJPv/QbZP7xbm1Q8
# ILHuatZHesWrgOkwmt7xpD9VTQoJNIp1KdJprZcPUL/4ygkCAwEAAaOB9DCB8TAf
# BgNVHSMEGDAWgBTa7WR0FJwUPKvdmam9WyhNizzJ2DAdBgNVHQ4EFgQUjmstM2v0
# M6eTsxOapeAK9xI1aogwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2Ny
# bC51c2VydHJ1c3QuY29tL1VUTi1VU0VSRmlyc3QtT2JqZWN0LmNybDA1BggrBgEF
# BQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20w
# DQYJKoZIhvcNAQEFBQADggEBALozJEBAjHzbWJ+zYJiy9cAx/usfblD2CuDk5oGt
# Joei3/2z2vRz8wD7KRuJGxU+22tSkyvErDmB1zxnV5o5NuAoCJrjOU+biQl/e8Vh
# f1mJMiUKaq4aPvCiJ6i2w7iH9xYESEE9XNjsn00gMQTZZaHtzWkHUxY93TYCCojr
# QOUGMAu4Fkvc77xVCf/GPhIudrPczkLv+XZX4bcKBUCYWJpdcRaTcYxlgepv84n3
# +3OttOe/2Y5vqgtPJfO44dXddZhogfiqwNGAwsTEOYnB9smebNd0+dmX+E/CmgrN
# Xo/4GengpZ/E8JIh5i15Jcki+cPwOoRXrToW9GOUEB1d0MYwggVdMIIERaADAgEC
# AhAm9aekh5J1NBCMCCQw/gnwMA0GCSqGSIb3DQEBCwUAMH0xCzAJBgNVBAYTAkdC
# MRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQx
# GjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYDVQQDExpDT01PRE8gUlNB
# IENvZGUgU2lnbmluZyBDQTAeFw0xNTAzMTkwMDAwMDBaFw0xNzAzMTgyMzU5NTla
# MIGnMQswCQYDVQQGEwJERTEOMAwGA1UEEQwFNjY1NzExETAPBgNVBAgMCFNhYXJs
# YW5kMRIwEAYDVQQHDAlFcHBlbGJvcm4xGTAXBgNVBAkMEEtvc3NtYW5zdHJhc3Nl
# IDcxIjAgBgNVBAoMGUtyw6RtZXIgSVQgU29sdXRpb25zIEdtYkgxIjAgBgNVBAMM
# GUtyw6RtZXIgSVQgU29sdXRpb25zIEdtYkgwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQC/R9waM/CNENun0EWELzCX5gtlh040ZxvClxSaPT4kHalvYSQr
# cydUgONVVRIoUAKu6Zq3QRnMeMOGizDhE6E88vOsgapKPIwNLLx4+DdV1yBlv+HF
# UDBtFCHSR4uD/dAkbj201hdb0OZlu4DSMZlxbi/p90AJQOdReL305B4roVOXR2P+
# rYQ3c21u+zVhP2wN5XJvt6pkBWK/cTpMjLDokTFC4Jmw6FSdPa7Jx8vim4Fr3xQE
# XjNa27UH/ywBPUYD6VQ8cA4p6c9n+9u6CpffclVDO/tfl1dSHC2m8XWu1/g6QQPM
# 9DULOIBtXFAiqipsUls59yYkjNm2tTDxJu7bAgMBAAGjggGsMIIBqDAfBgNVHSME
# GDAWgBQpkWD/ik366/mmarjP+eZLvUnOEjAdBgNVHQ4EFgQUOzijMeuxaqIXVTKq
# /JGBNkrrvVowDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAww
# CgYIKwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQDAgQQMEYGA1UdIAQ/MD0wOwYMKwYB
# BAGyMQECAQMCMCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5u
# ZXQvQ1BTMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29t
# L0NPTU9ET1JTQUNvZGVTaWduaW5nQ0EuY3JsMHQGCCsGAQUFBwEBBGgwZjA+Bggr
# BgEFBQcwAoYyaHR0cDovL2NydC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQ29kZVNp
# Z25pbmdDQS5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNv
# bTAdBgNVHREEFjAUgRJpbmZvQGtyYWVtZXItaXQuZGUwDQYJKoZIhvcNAQELBQAD
# ggEBAFoRdcq+rhGPXJvLaqFJzJYHmTzyiJ02PKa6FZJUn1x4FhptEaq7MTig1WW3
# dMhMjFuMf1gbiX1b3QcmPvjS+CklKgcSthsfODHzQH6YAdl9S7UjSA+PZVkZcMdx
# bIrGoh1RWz3fp2ax0+ViKqm46AQrhdVT11WrilxSAkCIS6T5F6ENEQj277wpPn3/
# mv5MghFEaxmkMsymlFFjk752YuqqmuXRkehQZZvoPbrPJY5YBdJwL5oy2VusTx9E
# 6dRYVeKJJWPnG3T5ogdWr6gAzRC3AtD6unMQ5hZs0Dth/PblQlFsr28Wxc1lAUq+
# J0wxbOBPm1z4dIiE5RSQXY6Ms7AwggXYMIIDwKADAgECAhBMqvnK22Nv4B/3Tthb
# A4adMA0GCSqGSIb3DQEBDAUAMIGFMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3Jl
# YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01P
# RE8gQ0EgTGltaXRlZDErMCkGA1UEAxMiQ09NT0RPIFJTQSBDZXJ0aWZpY2F0aW9u
# IEF1dGhvcml0eTAeFw0xMDAxMTkwMDAwMDBaFw0zODAxMTgyMzU5NTlaMIGFMQsw
# CQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQH
# EwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDErMCkGA1UEAxMi
# Q09NT0RPIFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAJHoVJLSClaxrA0k3cXPRGd0mSs3o30jcABxvFPf
# xPoqEo9LfxBWvZ9wcrdhf8lLDxenPeOwBGHu/xGXx/SGPgr6Plz5k+Y0etkUa+ec
# s4Wggnp2r3GQ1+z9DfqcbPrfsIL0FH75vsSmL09/mX+1/GdDcr0MANaJ62ss0+2P
# mBwUq37l42782KjkkiTaQ2tiuFX96sG8bLaL8w6NmuSbbGmZ+HhIMEXVreENPEVg
# /DKWUSe8Z8PKLrZr6kbHxyCgsR9l3kgIuqROqfKDRjeE6+jMgUhDZ05yKptcvUwb
# KIpcInu0q5jZ7uBRg8MJRk5tPpn6lRfafDNXQTyNUe0LtlyvLGMa31fIP7zpXcSb
# r0WZ4qNaJLS6qVY9z2+q/0lYvvCo//S4rek3+7q49As6+ehDQh6J2ITLE/HZu+GJ
# YLiMKFasFB2cCudx688O3T2plqFIvTz3r7UNIkzAEYHsVjv206LiW7eyBCJSlYCT
# aeiOTGXxkQMtcHQC6otnFSlpUgK7199QalVGv6CjKGF/cNDDoqosIapHziicBkV2
# v4IYJ7TVrrTLUOZr9EyGcTDppt8WhuDY/0Dd+9BCiH+jMzouXB5BEYFjzhhxayvs
# poq3MVw6akfgw3lZ1iAar/JqmKpyvFdK0kuduxD8sExB5e0dPV4onZzMv7NR2qdH
# 5YRTAgMBAAGjQjBAMB0GA1UdDgQWBBS7r34CPfqm8TyEjq3uOJjs2TIy1DAOBgNV
# HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQwFAAOCAgEA
# CvHVRoS3rlG7bLJNQRQAk0ycy+XAVM+gJY4C+f2wog31IJg8Ey2sVqKw1n4Rkuku
# up4umnKxvRlEbGE1opq0FhJpWozh1z6kGugvA/SuYR0QGyqki3rF/gWm4cDWyP6e
# ro8ruj2Z+NhzCVhGbqac9Ncn05XaN4NyHNNz4KJHmQM4XdVJeQApHMfsmyAcByRp
# V3iyOfw6hKC1nHyNvy6TYie3OdoXGK69PAlo/4SbPNXWCwPjV54U99HrT8i9hyO3
# tklDeYVcuuuSC6HG6GioTBaxGpkK6FMskruhCRh1DGWoe8sjtxrCKIXDG//QK2Lv
# pHsJkZhnjBQBzWgGamMhdQOAiIpugcaF8qmkLef0pSQQR4PKzfSNeVixBpvnGirZ
# nQHXlH3tA0rK8NvoqQE+9VaZyR6OST275Qm54E9Jkj0WgkDMzFnG5jrtEi5pPGyV
# sf2qHXt/hr4eDjJG+/sTj3V/TItLRmP+ADRAcMHDuaHdpnDiBLNBvOmAkepknHrh
# IgOpnG5vDmVPbIeHXvNuoPl1pZtA6FOyJ51KucB3IY3/h/LevIzvF9+3SQvR8m4w
# CxoOTnbtEfz16Vayfb/HbQqTjKXQwLYdvjpOlKLXbmwLwop8+iDzxOTlzQ2oy5GS
# sXyF7LUUaWYOgufNzsgtplF/IcE1U4UGSl2frbsbX3QwggXgMIIDyKADAgECAhAu
# fIfMDpNKUv6U/Ry3zTSvMA0GCSqGSIb3DQEBDAUAMIGFMQswCQYDVQQGEwJHQjEb
# MBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRow
# GAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDErMCkGA1UEAxMiQ09NT0RPIFJTQSBD
# ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xMzA1MDkwMDAwMDBaFw0yODA1MDgy
# MzU5NTlaMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0
# ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVk
# MSMwIQYDVQQDExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAKaYkGN3kTR/itHd6WcxEevMHv0xHbO5Ylc/
# k7xb458eJDIRJ2u8UZGnz56eJbNfgagYDx0eIDAO+2F7hgmz4/2iaJ0cLJ2/cuPk
# daDlNSOOyYruGgxkx9hCoXu1UgNLOrCOI0tLY+AilDd71XmQChQYUSzm/sES8Bw/
# YWEKjKLc9sMwqs0oGHVIwXlaCM27jFWM99R2kDozRlBzmFz0hUprD4DdXta9/akv
# wCX1+XjXjV8QwkRVPJA8MUbLcK4HqQrjr8EBb5AaI+JfONvGCF1Hs4NB8C4ANxS5
# Eqp5klLNhw972GIppH4wvRu1jHK0SPLj6CH5XkxieYsCBp9/1QsCAwEAAaOCAVEw
# ggFNMB8GA1UdIwQYMBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBQp
# kWD/ik366/mmarjP+eZLvUnOEjAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgw
# BgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDAzARBgNVHSAECjAIMAYGBFUdIAAw
# TAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5jb21vZG9jYS5jb20vQ09NT0RP
# UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwcQYIKwYBBQUHAQEEZTBjMDsG
# CCsGAQUFBzAChi9odHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01PRE9SU0FBZGRU
# cnVzdENBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29t
# MA0GCSqGSIb3DQEBDAUAA4ICAQACPwI5w+74yjuJ3gxtTbHxTpJPr8I4LATMxWMR
# qwljr6ui1wI/zG8Zwz3WGgiU/yXYqYinKxAa4JuxByIaURw61OHpCb/mJHSvHnsW
# MW4j71RRLVIC4nUIBUzxt1HhUQDGh/Zs7hBEdldq8d9YayGqSdR8N069/7Z1VEAY
# NldnEc1PAuT+89r8dRfb7Lf3ZQkjSR9DV4PqfiB3YchN8rtlTaj3hUUHr3ppJ2WQ
# KUCL33s6UTmMqB9wea1tQiCizwxsA4xMzXMHlOdajjoEuqKhfB/LYzoVp9QVG6dS
# RzKp9L9kR9GqH1NOMjBzwm+3eIKdXP9Gu2siHYgL+BuqNKb8jPXdf2WMjDFXMdA2
# 7Eehz8uLqO8cGFjFBnfKS5tRr0wISnqP4qNS4o6OzCbkstjlOMKo7caBnDVrqVhh
# SgqXtEtCtlWdvpnncG1Z+G0qDH8ZYF8MmohsMKxSCZAWG/8rndvQIMqJ6ih+Mo4Z
# 33tIMx7XZfiuyfiDFJN2fWTQjs6+NX3/cjFNn569HmwvqI8MBlD7jCezdsn05tfD
# NOKMhyGGYf6/VXThIXcDCmhsu+TJqebPWSXrfOxFDnlmaOgizbjvmIVNlhE8CYrQ
# f7woKBP7aspUjZJczcJlmAaezkhb1LU3k0ZBfAfdz/pD77pnYf99SeC7MH1cgOPm
# FjlLpzGCBHowggR2AgEBMIGRMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVh
# dGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9E
# TyBDQSBMaW1pdGVkMSMwIQYDVQQDExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBD
# QQIQJvWnpIeSdTQQjAgkMP4J8DAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUkq39ECsrWKlXzR74
# A7xwgvMt2BIwDQYJKoZIhvcNAQEBBQAEggEAX84Tk7cHtljYQlRXe+pD3+VjMGy+
# vZfLvJjEGJazbvCkHhzaYJbCFw70hi96GdJ/Aux5uKZTd1iTiSscCRBOm017Wf5I
# zWdehNtJm9enH7qVgbDYjlioZHJHtGegn7+J5MRvkpljpbHuTByMk0ADJh7uMLWJ
# ge/Pt8GFIzu6GGwT7fzOAb52YNSXpGH3ipyBTDEdLIxePOc8ihbU52OPizFExRRG
# 9sqQ/n4YxvKM1aXhcLO1AhUR3fnvVvqkwfTDaux74UpFF+HlwV+AvgIGAdAozQA8
# Q25yfzJbqdiB2d+QIGRkqjZaRzlomfx7/qwAlkqWzAqiLZD8MyHJg4eeJaGCAkMw
# ggI/BgkqhkiG9w0BCQYxggIwMIICLAIBATCBqTCBlTELMAkGA1UEBhMCVVMxCzAJ
# BgNVBAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2UgQ2l0eTEeMBwGA1UEChMVVGhl
# IFVTRVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExhodHRwOi8vd3d3LnVzZXJ0cnVz
# dC5jb20xHTAbBgNVBAMTFFVUTi1VU0VSRmlyc3QtT2JqZWN0Ag8WiPA5JV5jjmkU
# OQfmMwswCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTE3MDIwNjE1NDYwMVowIwYJKoZIhvcNAQkEMRYEFG4Fz/wg
# lgXnvqgE8IFP25q1e/ggMA0GCSqGSIb3DQEBAQUABIIBAGgGhJNKqg2/2Abv5Qx3
# jwPD6vftq66hSmE0TbSn69w/NowQb//U0i8Hk1on5BqzxhQYyin6iJMgs5G4uHGo
# MGK2tInroQycsBEQE6l3Ii3nbpZEaF+8AYM/qOJnhyjUN6r7Yjm6YQdVVnvBO8zx
# nx7IiY1k36dENPSsY7EWWkkM00nLXYkNSY1Arqmw6bJG7zAX+7ZZ0kON9sxVMWau
# vS5PMoJprFN7x0EyJeWubgFACUgfD76HszPfadggldMNkAs+KXqko7k4f8/eCi2V
# RKT4Ad8YKIUCUf4XvOfWHEvDVG+UW6mjxmsW0umORKj3Pcz25BAq/Htn2Ree38PS
# 3Gw=
# SIG # End signature block
