<#
.SYNOPSIS
    Script used to generate a self-signed certificate for protecting RDC Manager passwords
.DESCRIPTION
    This script can be used to generate a self-signed certificate for protecting RDC Manager passwords.

    The script first generates the certificate and exports it. It then removes the certificate from the Personal certificate store and re-imports it from the exported file.

    The reason this step is taken is to ensure that the exported certificate can be properly imported on other computers in the future.
.EXAMPLE
    PS C:\> GenerateRDCManCert.ps1 -CertificateName "RDCManCert" -CertificatePassword = "p@ssw0rd" -ExportFolder = "C:\Test"
    Generates a self-signed certificate named "RDCManCert" secured by the password "p@ssw0rd" and exports it to the folder "C:\Test".
.EXAMPLE
    PS C:\> $securePassword = ConvertTo-SecureString -String "p@ssw0rd" -AsPlainText -Force
    PS C:\> GenerateRDCManCert.ps1 -CertificateName "RDCManCert" -CertificateSecurePassword = $securePassword -ExportFolder = "C:\Test"
    This example first creates a securestring of the desired certificate password. This is then passed to the script, which generates a self-signed certificate named "RDCManCert", secured by the securestring password, and exports it to the folder "C:\Test".
.PARAMETER CertificateName
    Default = RDCManagerCertificate, Use to specify the subject and file names for the self-signed certificate.
.PARAMETER CertificatePassword
    Default = p@ssw0rd; Use to pass a plaintext string to the script, the contents of which will be converted to a SecureString and then used as the password to export and import the certificate.
.PARAMETER CertificateSecurePassword
    Use to pass a SecureString to the script, the contents of which will be used as the password to export and import the certificate.
.PARAMETER ExportFolder
    Default = C:\Test; Use to specify the location to which the certificate should be exported
.PARAMETER ValidityInYears
    Default = 5; Use to specify the number of years the generated certificate should be valid.
.NOTES
    Written by Gabriel Taylor, 2017

    Based on code written by Michael Nystrom, 2015
    https://deploymentbunny.com/2015/11/13/working-in-the-datacenter-protect-remote-desktop-connection-manager-using-self-signed-certificates/
#>

#region Parameters
    [CmdletBinding( DefaultParameterSetName = 'InsecurePassword' )]
    param
    (
        [string]
        $CertificateName = "RDCManagerCertificate",

        [parameter ( ParameterSetName = 'InsecurePassword' )]
        [string]
        $CertificatePassword = 'p@ssw0rd',

        [parameter (
            Mandatory = $true,
            ParameterSetName = 'SecurePassword'
        )]
        [securestring]
        $CertificateSecurePassword,

        [string]
        $ExportFolder = "C:\Test",

        [int]
        $ValidityInYears = 5
    )
#endregion

#region Variables
[datetime]$startTime = Get-Date
[string]$certificateStore = 'Cert:\CurrentUser\My'
[bool]$continueProcessing = $true
#endregion

#region Validate Inputs
    # Validate that the export folder exists
    $outputMessage = "Validating existence of export folder `"$ExportFolder`" ..."
    Write-Verbose -Message $outputMessage
    if ( ( Test-Path -Path $ExportFolder ) -ne $true )
    {
        # Attempt to create the folder
        try
        {
            # The folder does not exist; attempt to create it.
            $outputMessage = "Export folder `"$ExportFolder`" does not exist; attempting to create it ..."
            Write-Verbose -Message $outputMessage

            New-Item -ItemType Directory -Path $ExportFolder -ErrorAction Stop | Out-Null
            $outputMessage = "Export folder `"$ExportFolder`" created successfully."
            Write-Verbose -Message $outputMessage
        }
        catch
        {
            # Failed to create the folder; throw the error and do not proceed.
            $outputMessage = "Failed to create export folder `"$ExportFolder`"; error: $($_.Exception.Message)."
            throw $outputMessage
        }
    }
    else
    {
        # The folder already exists; all is well.
        $outputMessage = "Export folder already exists."
        Write-Verbose -Message $outputMessage
    }

    $outputMessage = "Formatting certificate subject and export file path ..."
    Write-Verbose -Message $outputMessage

    # Ensure the certificate name has no extension
    [string]$certificateSubject = $CertificateName -split '\.' | Select-Object -First 1
    $outputMessage = "Certificate subject will be = $certificateSubject"
    Write-Verbose -Message $outputMessage

    # Define the exported certificate file name
    [string]$certificateFileName = $certificateSubject + '.pfx'
    $outputMessage = "Exported certificate file name will be = $certificateFileName"
    Write-Verbose -Message $outputMessage

    # Define the output path for the exported certificate file
    [string]$certificateFilePath = Join-Path -Path $ExportFolder `
        -ChildPath $certificateFileName
    $outputMessage = "Exported certificate file path will be = $certificateFilePath"
    Write-Verbose -Message $outputMessage

    # Ensure the Certificate Password is a Secure String
    if ( $PSCmdlet.ParameterSetName -eq 'InsecurePassword' )
    {
        # The password needs to be converted into a Secure String
        try
        {
            $outputMessage = "The certificate password was supplied in an insecure format; converting to a SecureString ..."
            Write-Verbose -Message $outputMessage
            $CertificateSecurePassword = ConvertTo-SecureString `
                -String $CertificatePassword `
                -AsPlainText `
                -Force `
                -ErrorAction Stop
            $outputMessage = "Certificate password converted successfully."
            Write-Verbose -Message $outputMessage
        }
        catch
        {
            # Failed to secure the password; throw the error and do not proceed.
            $outputMessage = "Failed to convert the insecure password to a SecureString; error: $($_.Exception.Message)."
            throw $outputMessage
        }
    }
#endregion

#region Create Certificate
    # Create the certificate
    try
    {
        $outputMessage = "Attempting to create the certificate ..."
        Write-Verbose -Message $outputMessage
        $rdcManCertificate = New-SelfSignedCertificate `
            -CertStoreLocation $certificateStore `
            -Subject $certificateSubject `
            -KeyExportPolicy 'Exportable' `
            -KeySpec 'KeyExchange' `
            -NotAfter $(Get-Date).AddYears($ValidityInYears) `
            -ErrorAction Stop

        $outputMessage = "Certificate created successfully."
        Write-Verbose -Message $outputMessage
    }
    catch
    {
        # Throw an error
        $outputMessage = "Failed to create the certificate; error: $($_.Exception.Message)"
        throw $outputMessage
    }
#endregion

#region Export Certificate
    # Export the certificate
    try
    {
        # Export the certificate
        $outputMessage = "Attempting to export the certificate to `"$certificateFilePath`"..."
        Write-Verbose -Message $outputMessage
        Export-PfxCertificate -Cert $rdcManCertificate `
                -FilePath $certificateFilePath `
                -Password $CertificateSecurePassword |
            Out-Null

        $outputMessage = "Certificate exported successfully."
        Write-Verbose -Message $outputMessage
    }
    catch
    {
        # Write an error
        $outputMessage = "Failed to export the certificate; error: $($_.Exception.Message)"
        Write-Error -Message $outputMessage

        # Write a warning declaring the process state.
        $outputMessage = "The certificate has been created and can be used immediately, however since the export failed, it will be unavailable for import into any other computers. The issue cited in the previous error should be investigated and the certificate properly exported to guarantee the certificate is available for use on other computers."
        Write-Warning -Message $outputMessage

        # Flag a variable to prevent further processing
        $continueProcessing = $false
    }

    # Remove the certificate
    if ( $continueProcessing -eq $true )
    {
        try
        {
            $outputMessage = "Attempting to remove the certificate from `"$certificateStore`"..."
            Write-Verbose -Message $outputMessage
            $rdcManCertificate | Remove-Item -ErrorAction Stop

            $outputMessage = "Certificate removed successfully."
            Write-Verbose -Message $outputMessage
        }
        catch
        {
            # Write an error
            $outputMessage = "Failed to remove the certificate; error: $($_.Exception.Message)"
            Write-Error -Message $outputMessage

            # Write a warning declaring the process state.
            $outputMessage = "The certificate has been created and can be used immediately, however since it was unable to be removed, the script cannot confirm that the exported certificate file can be reimported successfully. Please manually test this by deleting the certificate and importing it from the exported certificate file or by importing the exported certificate file on another computer."
            Write-Warning -Message $outputMessage

            # Flag a variable to prevent further processing
            $continueProcessing = $false
        }
    }

#endregion

#region Import Certificate
if ( $continueProcessing -eq $true )
{
    try
    {
        # Attempt to import the certificate from the exported file
        $outputMessage = "Attempting to import the certificate from `"$certificateFilePath`"..."
        Write-Verbose -Message $outputMessage
        Import-PfxCertificate -CertStoreLocation $certificateStore `
                -Password $CertificateSecurePassword `
                -FilePath $certificateFilePath `
                -ErrorAction Stop |
            Out-Null

        $outputMessage = "Certificate imported successfully."
        Write-Verbose -Message $outputMessage
    }
    catch
    {
        # Write an error
        $outputMessage = "Failed to import the certificate; error: $($_.Exception.Message)"
        Write-Error -Message $outputMessage

        $outputMessage = "The exported certificate file cannot be imported. It will be deleted to avoid issues."
        Write-Warning -Message $outputMessage

        # Remove the unimportable file
        $outputMessage = "Attempting to delete exported certificate file ..."
        Write-Verbose -Message $outputMessage
        Get-Item -Path $certificateFilePath | Remove-Item -Force -ErrorAction Stop
        $outputMessage = "Exported certificate file was deleted successfully."
        Write-Verbose -Message $outputMessage
    }
}
#endregion

#region Wrap-Up
# Write the processing time
Write-Verbose -Message "Process Complete! Total run time: $( New-TimeSpan -Start $startTime -End (Get-Date) )"
#endregion
