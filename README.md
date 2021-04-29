# FinalEam
Final Exam ITNET-154
#PowewerShell - Final Exam
#Student Name: Jessica Gomez
#Course #:ITNET-154-900
#Date:04/27/2021
##########################################################

#Question #1
#No need to add scripts for this question


#region Question #2
#submitted by J.G
#date 04/27/2021

Test-NetConnection DC1, DC2, Client1 -Quiet

    Get-DnsServerZone -ComputerName DC1
    Get-DnsServerResourceRecord -ZoneName ITNET-154.pri

#endregion 


#region Question #3
#submitted by J.G
#date 02/27/2021

Add-WindowsFeature -IncludeManagementTools dhcp
netsh dhcp add securitygroups

Add-DhcpServerv4Scope `
        -Name “192.168.20.0” `
        -StartRange 192.168.20.240 `
        -EndRange 192.168.20.250 `
        -SubnetMask 255.255.255.0 `
        -ComputerName DC1 `
        -LeaseDuration 8:0:0:0 `
        -verbose
        
        Set-DhcpServerv4OptionValue  `
        -ScopeId 192.168.20.0 `
        -ComputerName DC1.ITNET-154.pri `
        -DnsServer 192.168.20.101 `
        -DnsDomain itnet-154.pri `
        -Router 192.168.20.1 `
        -Verbose

#endregion

#region Question #4
#submitted by J.G
#date 04/28/2010
New-ADOrganizationalUnit -Name DAs -Path "DC=ITNET-154, DC=pri"

New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "DomainAdmin1" `
-Enabled $true `
-Path "CN=Users, DC=ITNET-154, DC=pri" `
-SamAccountName DomainAdmin1 `
-UserPrincipalName ("DomainAdmin1@ITNET-154.pri")

New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "DomainAdmin2" `
-Enabled $true `
-Path "CN=Users, DC=ITNET-154, DC=pri" `
-SamAccountName DomainAdmin2 `
-UserPrincipalName ("DomainAdmin2@ITNET-154.pri")

Add-ADGroupMember -Identity 'Domain Admins' -Members 'DomainAdmin1','DomainAdmin2'

#endregion

#region Question #5
#submitted by J.G
#date04/29/2021
New-ADOrganizationalUnit -Name Employees -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Workstations -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name "Member Servers" -Path "DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Employees, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Employees, DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Workstations, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Workstations, DC=ITNET-154, DC=pri"

#endregion

#region Question #6 
#submitted by
#date
New-ADOrganizationalUnit -Name TempEmployees -Path "DC=ITNET-154, DC=pri"

$domainName = "ITNET-154.pri"
$path = "OU=TempEmployees,DC=ITNET-112,DC=pri"
$total=50

1..$total |foreach { 
$userName = "Worker$_"
Write-Host "Creating user $userName@$domainName.  User $_ of $total" 

New-ADUser -AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "$userName" `
-Enabled $true `
-Path $path `
-SamAccountName "$userName" `
-UserPrincipalName ($userName + "@" + $domainName)
}

#endregion

#region Question #7 
#submitted by
#date

New-ADGroup -GroupScope Global -Name "GG_Factory"
1..5 | foreach {Add-ADGroupMember -Identity "GG_Factory" -Members "Worker$_" }

#endregion

#region Question #8
#submitted by
#date
NewADGroup -GroupScope Global -Name "GG_Office"
6..10 | foreach {Add-ADGroupMember -Identity "GG_Office" -Members "Worker$_" }


#endregion

#region Question #9
#submitted by J.G
#date 04/29/2021
$factory ="OU=Factory,OU=Employees,DC=ITNET-154,DC=pri"
$office = "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"

for ($UserIndex=1; $UserIndex -le 5; $UserIndex++)
{

$userName = "Worker$userIndex"
$user = get-aduser $userName
Write-Host "Moving user $user.DistinguishedName to $factory" 
Move-ADObject $user -TargetPath $factory
}

for ($UserIndex=6; $UserIndex -le 10; $UserIndex++)
{

$userName = "Worker$userIndex"
$user = get-aduser $userName
Write-Host "Moving user $user.DistinguishedName to $office" 
Move-ADObject $user -TargetPath $office
}


#region Question #10
#submitted by J.G 04/29/2021
#date
New-ADGroup -GroupScope Global -Name "GG_AllEmpolyees" 

Add-ADGroupMember -Identity "GG_AllEmployees" -Members "GG_Factory"
Add-ADGroupMember -Identity "GG_AllEmployees" -Members "GG_Office"

#endregion 
