:setup_local
    if "%ManifestCertificateThumbprint%"=="" goto :setup_azure
    set SigningProvider=/sha1 "%ManifestCertificateThumbprint%"
    set TimestampServer=%ManifestTimestampRFC3161Url%
    goto :eof

:setup_azure
    if not exist "%APPDATA%\Microsoft.Trusted.Signing.Client.json" goto :eof
    set SigningProvider=/dlib "%USERPROFILE%\.nuget\packages\microsoft.trusted.signing.client\1.0.53\bin\x64\Azure.CodeSigning.Dlib.dll" /dmdf "%APPDATA%\Microsoft.Trusted.Signing.Client.json"
    set TimestampServer=http://timestamp.acs.microsoft.com
    goto :eof
