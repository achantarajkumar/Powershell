New-item -path c:\DFS_Audit\csv_$((get-date).ToString('dd-MM-yyyy')) -ItemType Directory
Start-Transcript -Append c:\DFS_Audit\csv_$((get-date).ToString('dd-MM-yyyy'))\list_Trans_list1.txt
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value '*' -Confirm:$false -Force
    Import-Module DFSN
    Import-Module Activedirectory


function Get-DomainSearcher {

        param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [String]
        $username1,
        
        [String]
        $password
         
    )

    if(!$Domain) {
        $Domain = (Get-NetDomain).name
    }
    else {
        if(!$DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC
                # to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController +":389" + "/"
    }
    if($ADSprefix) {
        $SearchString += $ADSprefix + ","
    }

    if($ADSpath) {
        if($ADSpath -like "GC://*") {
            # if we're searching the global catalog
            $DistinguishedName = $AdsPath
            $SearchString = ""
        }
        else {
            if($ADSpath -like "LDAP://*") {
                $ADSpath = $ADSpath.Substring(7)
            }
            $DistinguishedName = $ADSpath
        }
    }
    else {
        $DistinguishedName = "DC=$($Domain.Replace('.', ',DC='))"
    }

    $SearchString += $DistinguishedName
   # Write-Verbose "Get-DomainSearcher search string: $SearchString"


  #3 $password12 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        
   
    $de = New-Object DirectoryServices.DirectoryEntry($SearchString,$username1,$password)
    
    return $de
}

Function MyFunction ([String] $Server1,[String] $DomainUserName, [String] $pp) 
{
Write-Host "Called"
    $shortname = $Server1.split('.')[0]
    $domainname = $Server1 -split $server1.split('.')[0]+"."
    $dnssuf = $domainname[1]

     $NewShare = @{
    VMName = ""
    Share = ""
    SharePath = ""
    AccessGroup = ""
    AccessType = ""
    AccessLevel= ""
    }

$global:VMArray = @()
    

$Vars1=$Server1

$arrComputers = @($Vars1)


   
$pwdSecureString = ConvertTo-SecureString -Force -AsPlainText $pp

$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainUserName, $pwdSecureString

ForEach ($strComputer in $arrComputers)
{

$credential
     $session = New-CimSession -ComputerName $strComputer -Credential $credential
         
       $objWMI = Get-CimInstance -Class "Win32_share" -CimSession $session 
       $colACLs = $objWMI
      
      $colACLs 

      foreach ($share in $colACLs) {
    
    if ($share.Type -eq 18) {
        Write-Host "iSCSI Share: $($share.Name)"
    } elseif ($share.Type -eq 0) {
        Write-Host "Windows Share: $($share.Name)"
    
               $folder=$share.Name
               if ($folder -inotlike '*$')
               {
               #$security = Get-CimInstance -ClassName Win32_LogicalShareSecuritySetting -Filter "Name='$folder'" -CimSession $session
               $security = Get-WmiObject -class Win32_LogicalShareSecuritySetting -Filter "Name='$folder'"  -ComputerName $strComputer -Credential $credential
               $descriptor = $security.GetSecurityDescriptor().Descriptor
               Write-Host "DACL: $($folder)" 
               $descriptor.Dacl | ForEach-Object {
               $account = $_.Trustee.Name
               #    $access = $_.AccessMask
               $access = [System.Security.AccessControl.FileSystemRights] $_.AccessMask
                $type = $_.AceType
    
                if ($type -eq "Allow") {
                $accessType = "allowed"
                }
                    else {
                    $accessType = "denied"
                    }

      
    $NewShare.VMName = $strComputer
    $NewShare.Share = $share.Name
    $NewShare.SharePath = $share.path
    $NewShare.AccessGroup = $account
    $NewShare.AccessType = $accessType
    $NewShare.AccessLevel= ($access).ToString().Replace(", Synchronize","")
    
    
    
    $new = New-Object PSObject -Property $NewShare
    
    $global:VMArray += $New
    }
    }
    }  
    }
                  
    return $global:VMArray
    }


function Get-NetDomain {

    [CmdletBinding()]
    param( 
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain
    )

    process {
        if($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
    }
}

$Domain = Read-Host -Prompt "Enter your Domain name"
$DomainController =  Read-Host -Prompt "Enter Ip Address of LDAP Server (389 Port)"
$UserName = Read-Host -Prompt "Enter UserName"
$password = Read-Host "Enter Password" -AsSecureString


$PageSize = 1000

$password12 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

$DFSsearchere = Get-DomainSearcher -Domain $Domain -DomainController $DomainController  -PageSize $PageSize -username $UserName -password $password12 



        if($DFSsearchere) {
            $DFSshares = @()
            $DFSSearcher =  New-Object DirectoryServices.DirectorySearcher($DFSsearchere)
            $DFSsearcher.Filter = "(&(objectClass=msDFS-Linkv2))"
            $DFSSearcher.PropertiesToLoad.Add(('msDFS-TargetListv2'))
            $DFSSearcher.PropertiesToLoad.Add(('msDFS-LinkPathv2'))
               # $DFSSearcher.FindAll()
                          try {
                
                $DFSSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $target_list = $Properties.'msdfs-targetlistv2'[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                    $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                        try {
                            $Target = $_.InnerText
                            if ( $Target.Contains('\') ) {
                                $DFSroot = $Target.split("\")[3]
                                $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Debug "Error in parsing target : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Get-DFSshareV2 error : $_"
            }
            $DFSshares | Sort-Object -Unique -Property "RemoteServerName"
 
        }
 
$DFSInfo = @()
$DFSInfo =$DFSshares| Sort-Object -Unique -Property "RemoteServerName"
$Server1Info=@()
$server1=@()
$serverInfo1 = @()


ForEach ($DFSObject in $DFSInfo)
{
	$serverName = [String]$DFSObject.RemoteServerName
try{
   $new = [System.Net.Dns]::GetHostByName($serverName).hostname
   }catch{}
   Try{
   $ips = Resolve-DnsName $new | Select -First 1|Select-Object IPAddress
   $TestPing = Test-Connection -ComputerName $ips.IPAddress.ToString()
    ($TestPing | Measure-Object -Property ResponseTimeToLive -Average ).average
   }catch{}
     
    
    if (($TestPing  |Measure-Object -Property ResponseTimeToLive -Average ).Average -ge 120)
    {         

    $server1 += $New
    
     }   
}

$serverInfo1 = $Server1| Sort-Object -Property @{Expression={$_.Trim()}} -Unique
$global:VMCSV = @()

foreach ($server in $serverInfo1)
{
	if ($server -ne '')
    {
	
    $server 
    $password1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    
   $global:VMCSV += MyFunction  $server  $UserName  $password1
     
}

}




$Filename = "C:\DFS_Audit\csv_$(get-date -f dd-MM-yyyy)\DFSPermissions_$($Domain).csv"
$Filename1 = "C:\DFS_Audit\csv_$(get-date -f dd-MM-yyyy)\Temp.csv"
 $global:VMCSV|Select-Object VMName,Share,Sharepath,Accessgroup,AccessLevel|export-csv $Filename -NoTypeInformation
 Import-Csv -Path "$($filename)" | Where-Object { $_.PSObject.Properties.Value -ne '' } | Export-Csv -Path "$($Filename1)" -NoTypeInformation
 Remove-Item -Path $Filename
 Rename-Item -Path $Filename1 $Filename

   
 
 

$sourcefolder = "C:\DFS_Audit\csv_$(get-date -f dd-MM-yyyy)"
$sourcefiles = Get-ChildItem -Path $sourcefolder -Filter *.csv
$result = @()
foreach ($file in $sourcefiles) {
    $data = Import-Csv $file.FullName
    $result += $data
}
$result | Export-Csv -path C:\DFS_Audit\csv_$(get-date -f dd-MM-yyyy)\DFS_merged_$((Get-Date).ToString('dd-MM-yyyy')).csv -NoTypeInformation
$result


$From = "achantarajkumar@hotmail.com"
$To = "achantarajkumar@hotmail.com"

$Attachment = "c:\DFS_Audit\csv_$(get-date -f dd-MM-yyyy)\DFS_merged_$((Get-Date).ToString('dd-MM-yyyy')).csv"
$Subject = "Weekly Report DFS Permission $(get-date -f dd-MM-yyyy)"
$Body = "<h2>Take a look at windows Share permission this week</h2><br><br>"
$Body += " Please find the attached "
$SMTPServer = "mailrelay.amer.epiqcorp.com"
#$SMTPPort = "587"
Send-MailMessage -From $From -to $To -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer   -Attachments $Attachment

Stop-Transcript



#winrm s winrm/config/client @{TrustedHosts="*"}
