# GenerateRDCManCert

This PowerShell script generates a self-signed certificate which can be used to encrypt passwords in Remote Desktop Connection Manager. It also exports the certificate and validates that it can be reimported successfully so that the certificate can be moved to and installed upon other computers, thus ensuring the ability to use encrypted passwords on multiple computers.

This script is based off of code provided by Michael Nystrom in his blog post:

https://deploymentbunny.com/2015/11/13/working-in-the-datacenter-protect-remote-desktop-connection-manager-using-self-signed-certificates/

