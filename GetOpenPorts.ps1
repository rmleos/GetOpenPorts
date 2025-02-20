function get-OpenPorts {
  param(
      [Parameter(
        Position=0,
        HelpMessage="CIDR range must be in IPaddress with routing prfix, example 192.168.1.0/24",
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$CIDRAddress,
      [Parameter(
        Position=0,
        HelpMessage="Must be a list IP or IPs, example (192.168.1.1,192.169.10.3)",
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$Address,
      [Parameter(
        Position=1,
        HelpMessage="Can contain TCP Ports or Port to scan, example (135,445,80)",
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$TCPPorts,
      [Parameter(
        Position=2,
        HelpMessage="Can contain UDP Ports or Port to scan, example (53,68,110)",
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$UDPPorts,
      [Parameter(
        Position=3,
        HelpMessage="Use switch to show only open ports.",
        ValueFromPipelineByPropertyName=$true)]
        [switch]$ShowOpen

    )

    <#Port scanner functions port-scan-tcp & port-scan-udp
    Source: https://www.infosecmatter.com/minimalistic-tcp-and-udp-port-scanner/
    # Examples:
    #
    # port-scan-tcp 10.10.0.1 137
    # port-scan-tcp 10.10.0.1 (135,137,445)
    # port-scan-tcp (gc .\ips.txt) 137
    # port-scan-tcp (gc .\ips.txt) (135,137,445)


    # port-scan-udp 10.10.0.1 137
    # port-scan-udp 10.10.0.1 (135,137,445)
    # port-scan-udp (gc .\ips.txt) 137
    # port-scan-udp (gc .\ips.txt) (135,137,445)
        #>
    Function port-scan-tcp {
      param($hosts,$ports)
      if (!$ports) {
        Write-Host "usage: test-port-tcp <host|hosts> <port|ports>"
        Write-Host " e.g.: test-port-tcp 192.168.1.2 445`n"
        return
      }
      $out = ".\scanresults.txt"
      foreach($p in [array]$ports) {
       foreach($h in [array]$hosts) {
        $x = (gc $out -EA SilentlyContinue | select-string "^$h,tcp,$p,")
        if ($x) {
          gc $out | select-string "^$h,tcp,$p,"
          continue
        }
        $msg = "$h,tcp,$p,"
        $t = new-Object system.Net.Sockets.TcpClient
        $c = $t.ConnectAsync($h,$p)
        for($i=0; $i -lt 10; $i++) {
          if ($c.isCompleted) { break; }
          sleep -milliseconds 100
        }
        $t.Close();
        $r = "Filtered"
        if ($c.isFaulted -and $c.Exception -match "actively refused") {
          $r = "Closed"
        } elseif ($c.Status -eq "RanToCompletion") {
          $r = "Open"
        }
        $msg += $r
        $msg
       }
      }
        }

    Function port-scan-udp {
      param($hosts,$ports)
      if (!$ports) {
        Write-Host "usage: test-port-udp <host|hosts> <port|ports>"
        Write-Host " e.g.: test-port-udp 192.168.1.2 445`n"
        return
      }
      $out = ".\scanresults.txt"
      foreach($p in [array]$ports) {
       foreach($h in [array]$hosts) {
        $x = (gc $out -EA SilentlyContinue | select-string "^$h,udp,$p,")
        if ($x) {
          gc $out | select-string "^$h,udp,$p,"
          continue
        }
        $msg = "$h,udp,$p,"
        $u = new-object system.net.sockets.udpclient
        $u.Client.ReceiveTimeout = 500
        $u.Connect($h,$p)
        # Send a single byte 0x01
        [void]$u.Send(1,1)
        $l = new-object system.net.ipendpoint([system.net.ipaddress]::Any,0)
        $r = "Filtered"
        try {
          if ($u.Receive([ref]$l)) {
            # We have received some UDP data from the remote host in return
            $r = "Open"
          }
        } catch {
          if ($Error[0].ToString() -match "failed to respond") {
            # We haven't received any UDP data from the remote host in return
            # Let's see if we can ICMP ping the remote host
            if ((Get-wmiobject win32_pingstatus -Filter "address = '$h' and Timeout=1000 and ResolveAddressNames=false").StatusCode -eq 0) {
              # We can ping the remote host, so we can assume that ICMP is not
              # filtered. And because we didn't receive ICMP port-unreachable before,
              # we can assume that the remote UDP port is open
              $r = "Open"
            }
          } elseif ($Error[0].ToString() -match "forcibly closed") {
            # We have received ICMP port-unreachable, the UDP port is closed
            $r = "Closed"
          }
        }
        $u.Close()
        $msg += $r
        $msg
       }
      }
        }

    <#  
    .SYNOPSIS  
        Gets extended information about an IPv4 network.
    .DESCRIPTION  
        Gets Network Address, Broadcast Address, Wildcard Mask.
        and usable host range for a network given the 
        IP address and Subnet Mask.

    .PARAMETER IPAddress 
    IP Address of any ip within the network
    Note: Exclusive from @CIDRAddress

    .PARAMETER SubnetMask
    Subnet Mask of the network.
    Note: Exclusive from @CIDRAddress

    .PARAMETER CIDRAddress
    CIDR Notation of IP/Subnet Mask (x.x.x.x/y)
    Note: Exclusive from @IPAddress and @SubnetMask

    .PARAMETER IncludeIPRange
    Switch parameter that defines whether or not the script will return an array
    of usable host IP addresses within the defined network.
    Note: This parameter can cause delays in script completion for larger subnets.

    .EXAMPLE
    Get-IPv4NetworkInfo -IPAddress 192.168.1.23 -SubnetMask 255.255.255.0

    Get network information with IP Address and Subnet Mask

    .EXAMPLE
    Get-IPv4NetworkInfo -CIDRAddress 192.168.1.23/24

    Get network information with CIDR Notation

    .NOTES  
        File Name  : Get-IPv4NetworkInfo.ps1
        Author     : Ryan Drane
        Date       : 5/10/16
        Requires   : PowerShell v3
    .LINK  
    www.ryandrane.com
        #>
    Function Get-IPv4NetworkInfo{
        Param
        (
            [Parameter(ParameterSetName="IPandMask",Mandatory=$true)] 
            [ValidateScript({$_ -match [ipaddress]$_})] 
            [System.String]$IPAddress,

            [Parameter(ParameterSetName="IPandMask",Mandatory=$true)] 
            [ValidateScript({$_ -match [ipaddress]$_})] 
            [System.String]$SubnetMask,

            [Parameter(ParameterSetName="CIDR",Mandatory=$true)] 
            [ValidateScript({$_ -match '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[0-2][0-9]|3[0-2])$'})]
            [System.String]$CIDRAddress,

            [Switch]$IncludeIPRange
        )

        # If @CIDRAddress is set
        if($CIDRAddress)
        {
             # Separate our IP address, from subnet bit count
            $IPAddress, [int32]$MaskBits =  $CIDRAddress.Split('/')

            # Create array to hold our output mask
            $CIDRMask = @()

            # For loop to run through each octet,
            for($j = 0; $j -lt 4; $j++)
            {
                # If there are 8 or more bits left
                if($MaskBits -gt 7)
                {
                    # Add 255 to mask array, and subtract 8 bits 
                    $CIDRMask += [byte]255
                    $MaskBits -= 8
                }
                else
                {
                    # bits are less than 8, calculate octet bits and
                    # zero out our $MaskBits variable.
                    $CIDRMask += [byte]255 -shl (8 - $MaskBits)
                    $MaskBits = 0
                }
            }

            # Assign our newly created mask to the SubnetMask variable
            $SubnetMask = $CIDRMask -join '.'
        }

        # Get Arrays of [Byte] objects, one for each octet in our IP and Mask
        $IPAddressBytes = ([ipaddress]::Parse($IPAddress)).GetAddressBytes()
        $SubnetMaskBytes = ([ipaddress]::Parse($SubnetMask)).GetAddressBytes()

        # Declare empty arrays to hold output
        $NetworkAddressBytes   = @()
        $BroadcastAddressBytes = @()
        $WildcardMaskBytes     = @()

        # Determine Broadcast / Network Addresses, as well as Wildcard Mask
        for($i = 0; $i -lt 4; $i++)
        {
            # Compare each Octet in the host IP to the Mask using bitwise
            # to obtain our Network Address
            $NetworkAddressBytes +=  $IPAddressBytes[$i] -band $SubnetMaskBytes[$i]

            # Compare each Octet in the subnet mask to 255 to get our wildcard mask
            $WildcardMaskBytes +=  $SubnetMaskBytes[$i] -bxor 255

            # Compare each octet in network address to wildcard mask to get broadcast.
            $BroadcastAddressBytes += $NetworkAddressBytes[$i] -bxor $WildcardMaskBytes[$i] 
        }

        # Create variables to hold our NetworkAddress, WildcardMask, BroadcastAddress
        $NetworkAddress   = $NetworkAddressBytes -join '.'
        $BroadcastAddress = $BroadcastAddressBytes -join '.'
        $WildcardMask     = $WildcardMaskBytes -join '.'

        # Now that we have our Network, Widcard, and broadcast information, 
        # We need to reverse the byte order in our Network and Broadcast addresses
        [array]::Reverse($NetworkAddressBytes)
        [array]::Reverse($BroadcastAddressBytes)

        # We also need to reverse the array of our IP address in order to get its
        # integer representation
        [array]::Reverse($IPAddressBytes)

        # Next we convert them both to 32-bit integers
        $NetworkAddressInt   = [System.BitConverter]::ToUInt32($NetworkAddressBytes,0)
        $BroadcastAddressInt = [System.BitConverter]::ToUInt32($BroadcastAddressBytes,0)
        $IPAddressInt        = [System.BitConverter]::ToUInt32($IPAddressBytes,0)

        #Calculate the number of hosts in our subnet, subtracting one to account for network address.
        $NumberOfHosts = ($BroadcastAddressInt - $NetworkAddressInt) - 1

        # Declare an empty array to hold our range of usable IPs.
        $IPRange = @()

        # If -IncludeIPRange specified, calculate it
        if ($IncludeIPRange)
        {
            # Now run through our IP range and figure out the IP address for each.
            For ($j = 1; $j -le $NumberOfHosts; $j++)
            {
                # Increment Network Address by our counter variable, then convert back
                # lto an IP address and extract as string, add to IPRange output array.
                $IPRange +=[ipaddress]([convert]::ToDouble($NetworkAddressInt + $j)) | Select-Object -ExpandProperty IPAddressToString
            }
        }

        # Create our output object
        $obj = New-Object -TypeName psobject

        # Add our properties to it
        Add-Member -InputObject $obj -MemberType NoteProperty -Name "IPAddress"           -Value $IPAddress
        Add-Member -InputObject $obj -MemberType NoteProperty -Name "SubnetMask"          -Value $SubnetMask
        Add-Member -InputObject $obj -MemberType NoteProperty -Name "NetworkAddress"      -Value $NetworkAddress
        Add-Member -InputObject $obj -MemberType NoteProperty -Name "BroadcastAddress"    -Value $BroadcastAddress
        Add-Member -InputObject $obj -MemberType NoteProperty -Name "WildcardMask"        -Value $WildcardMask
        Add-Member -InputObject $obj -MemberType NoteProperty -Name "NumberOfHostIPs"     -Value $NumberOfHosts
        Add-Member -InputObject $obj -MemberType NoteProperty -Name "IPRange"             -Value $IPRange

        # Return the object
        return $obj
        }

    if ($CIDRAddress)
    {
        $IncludeIPRange = Get-IPv4NetworkInfo -CIDRAddress "$CIDRAddress" -IncludeIPRange -ErrorAction Stop
        $iprange = $IncludeIPRange.IPRange
    }
    if ($Address)
    {
        $iprange = $Address.Split(",")
    }
    $results = @()

    foreach ($ip in $iprange)
        {
            if ($TCPPorts)
            {
                if ($ShowOpen)
                {
                    $scanresult = port-scan-tcp $ip $TCPPorts
                    foreach ($result in $scanresult)
                    {
                        if ($result -match 'Open')
                        {
                            $results += $result
                        }
                    }

                }
                else
                {
                    $results += (port-scan-tcp $ip $TCPPorts)
                }
            }

            if ($UDPPorts)
            {
                if ($ShowOpen)
                {
                    $scanresult = port-scan-udp $ip $UDPPorts
                    foreach ($result in $scanresult)
                    {
                        if ($result -match 'Open')
                        {
                            $results += $result
                        }
                    }

                }
                else
                {
                    $results += (port-scan-udp $ip $UDPPorts)
                }
            }

        }

    $results
    }