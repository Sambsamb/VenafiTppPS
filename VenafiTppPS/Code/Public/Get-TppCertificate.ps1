function Get-TppCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('CertificateDN')]
        [String] $Path,

        [Parameter()]
        [ValidateSet("Base64", "Base64 (PKCS #8)", "DER", "PKCS #7", "PKCS #12")]
        [String] $Format = "PKCS #7",

        [Parameter()]
        [Security.SecureString] $SecurePassword,

        # [Parameter()]
        # [Bool]$IncludePrivateKey = $true,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {
                if (Test-Path $_ -PathType Container) {
                    $true
                } else {
                    Throw "Output path $_ does not exist"
                }
            })]
        [String] $OutPath,

        [Parameter()]
        [TppSession] $TppSession = $Script:TppSession
    )

    $TppSession.Validate()

    $plainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))

    $params = @{
        TppSession = $TppSession
        Method     = 'Post'
        UriLeaf    = 'certificates/retrieve'
        Body       = @{
            CertificateDN = $Path
            Format        = $Format
            # IncludePrivateKey = $IncludePrivateKey
            # Password          = $plainTextPassword
        }
    }

    $response = Invoke-TppRestMethod @params

    if ( $response.PSobject.Properties.name -contains "CertificateData" ) {
        $outFile = join-path $OutPath ($response.FileName)
        $bytes = [Convert]::FromBase64String($response.CertificateData)
        [IO.File]::WriteAllBytes($outFile, $bytes)
        write-verbose ('Saved {0} of format {1}' -f $outFile, $response.Format)
    } else {
        # we failed
    }

}
