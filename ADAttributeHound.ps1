function ADAttributeHound {
    <#
    .SYNOPSIS
        Exports Active Directory custom attributes to BloodHound OpenGraph JSON format.
    
    .DESCRIPTION
        Queries Active Directory for objects with populated custom attributes and exports the data in 
        BloodHound OpenGraph schema format. The output extends existing AD objects with additional 
        custom attribute data for enhanced attack path analysis.
        
        Uses .NET DirectoryServices for better performance and no module dependencies.
        
        In BloodHound Enterprise, OpenGraph attributes persist on AD objects until explicitly updated,
        removed, or the AD object is deleted after retention period (default: 7 days).
    
    .PARAMETER Attribute
        Specifies which Active Directory custom attribute(s) to collect (e.g., CustomAttribute1, CustomAttribute15,
        extensionAttribute1, or any other attribute name). Can specify multiple attributes as an array for batch processing.
        
    .PARAMETER ObjectType
        Specifies which AD object types to query. Valid values: User, Computer, Group.
        Can specify multiple types as an array. Required parameter.
    
    .PARAMETER OutputPath
        Specifies the directory where the output JSON file will be saved. 
        Default is current directory.
    
    .PARAMETER FileName
        Name of the output file. If not specified, defaults to 'OpenGraph_[Attribute]_[timestamp].json'.
    
    .PARAMETER SourceKind
        Specifies the source_kind metadata value for the OpenGraph data. This identifies the source
        of the data within BloodHound. Default is 'CustomAttributes'.
    
    .PARAMETER SearchBase
        Distinguished Name of the OU to search. If not specified, searches entire domain.
    
    .PARAMETER Server
        Domain Controller to query. If not specified, uses default DC.
    
    .PARAMETER IncludeEmpty
        Include objects even if the attribute value is empty or null.
    
    .PARAMETER PassThru
        Returns the graph object in addition to saving the file.
    
    .EXAMPLE
        ADAttributeHound -Attribute "extensionAttribute1" -ObjectType User
        
        Exports extensionAttribute1 data for all AD users to current directory.
    
    .EXAMPLE
        ADAttributeHound -Attribute "CustomAttribute5" -ObjectType User,Computer -OutputPath "C:\temp"
        
        Exports CustomAttribute5 data for users and computers to C:\temp.
    
    .EXAMPLE
        ADAttributeHound -Attribute "department" -ObjectType User,Group -SearchBase "OU=IT,DC=contoso,DC=com"
        
        Exports 'department' attribute for users and groups in the IT OU only.
    
    .EXAMPLE
        ADAttributeHound -Attribute "department" -ObjectType Computer -Server "DC01.contoso.com"
        
        Exports department attribute for computers, querying specific domain controller.
    
    .EXAMPLE
        ADAttributeHound -Attribute "extensionAttribute1","extensionAttribute2","department" -ObjectType User
        
        Batch exports multiple attributes for users in a single run.
    
    .NOTES
        Requirements:
        - PowerShell 5.1 or higher
        - Read access to Active Directory  
        - BloodHound v8.0+ for data ingestion
        
        Uses .NET DirectoryServices for optimal performance and no module dependencies.
        
        To ingest: Administration > File Ingest in BloodHound, upload the JSON file.
    
    .LINK
        https://bloodhound.specterops.io/opengraph/overview
    #>
    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Attribute,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Computer', 'Group')]
        [string[]]$ObjectType,
        
        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                return $true  # Allow empty, will use current directory
            }
            if (-not (Test-Path -Path $_ -PathType Container)) {
                throw "Directory '$_' does not exist"
            }
            return $true
        })]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [ValidatePattern('\.json$')]
        [string]$FileName,
        
        [Parameter(Mandatory = $false)]
        [string]$SourceKind = "CustomAttributes",
        
        [Parameter(Mandatory = $false)]
        [string]$SearchBase,
        
        [Parameter(Mandatory = $false)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeEmpty,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    begin {
        # Add .NET types
        Add-Type -AssemblyName System.DirectoryServices
        
        # Use current location if OutputPath not specified
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = (Get-Location).Path
        }
        
        # Generate filename with timestamp if not provided
        if (-not $FileName) {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            if ($Attribute.Count -eq 1) {
                $sanitizedAttribute = $Attribute[0] -replace '[^\w]', '_'
                $FileName = "OpenGraph_${sanitizedAttribute}_$timestamp.json"
            } else {
                $FileName = "OpenGraph_MultiAttribute_$timestamp.json"
            }
        }
        
        # Build output file path
        $outputFile = Join-Path -Path $OutputPath -ChildPath $FileName
        
        # Build LDAP path with proper escaping
        $ldapPath = $null
        try {
            if ($Server -and $SearchBase) {
                $ldapPath = "LDAP://$Server/$SearchBase"
            } elseif ($Server) {
                $ldapPath = "LDAP://$Server"
            } elseif ($SearchBase) {
                $ldapPath = "LDAP://$SearchBase"
            } else {
                # Get current domain
                $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $ldapPath = "LDAP://$($currentDomain.Name)"
            }
        } catch {
            throw "Failed to determine LDAP path: $_"
        }
        
        Write-Verbose "LDAP Path: $ldapPath"
        Write-Host "Starting export of attribute(s): $($Attribute -join ', ') for object types: $($ObjectType -join ', ')" -ForegroundColor Green
    }
    
    process {
        # Use hashtable for O(1) node lookups by SID
        $nodeIndex = @{}
        $allNodes = New-Object System.Collections.ArrayList
        
        try {
            # Process each attribute
            foreach ($attr in $Attribute) {
                Write-Host "`nProcessing attribute: $attr" -ForegroundColor Cyan
                
                # Process each object type
                foreach ($objType in $ObjectType) {
                    Write-Verbose "Processing $objType objects for attribute '$attr'..."
                    
                    # Build LDAP filter based on object type
                    $filter = switch ($objType) {
                        'User' {
                            if ($IncludeEmpty) {
                                "(&(objectCategory=person)(objectClass=user))"
                            } else {
                                "(&(objectCategory=person)(objectClass=user)($attr=*))"
                            }
                        }
                        'Computer' {
                            if ($IncludeEmpty) {
                                "(objectClass=computer)"
                            } else {
                                "(&(objectClass=computer)($attr=*))"
                            }
                        }
                        'Group' {
                            if ($IncludeEmpty) {
                                "(objectClass=group)"
                            } else {
                                "(&(objectClass=group)($attr=*))"
                            }
                        }
                    }
                    
                    # Create DirectorySearcher with proper resource management
                    $searcher = $null
                    $results = $null
                    
                    try {
                        $searcher = New-Object System.DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                        $searcher.PageSize = 1000
                        $searcher.Filter = $filter
                        
                        # Only load required properties
                        [void]$searcher.PropertiesToLoad.Add("objectSid")
                        [void]$searcher.PropertiesToLoad.Add($attr)
                        [void]$searcher.PropertiesToLoad.Add("distinguishedName")
                        [void]$searcher.PropertiesToLoad.Add("samAccountName")
                        
                        Write-Verbose "Executing search with filter: $filter"
                        
                        # Execute search
                        $results = $searcher.FindAll()
                        
                        if ($results.Count -eq 0) {
                            Write-Warning "No $objType objects found with '$attr'"
                            continue
                        }
                        
                        Write-Host "Found $($results.Count) $objType object(s) with '$attr'" -ForegroundColor Yellow
                        
                        # Process each result
                        foreach ($result in $results) {
                            try {
                                # Validate objectSid exists
                                if (-not $result.Properties.Contains("objectSid") -or $result.Properties["objectSid"].Count -eq 0) {
                                    $dn = if ($result.Properties.Contains("distinguishedName")) { 
                                        $result.Properties["distinguishedName"][0] 
                                    } else { 
                                        "Unknown" 
                                    }
                                    Write-Warning "Object missing SID, skipping: $dn"
                                    continue
                                }
                                
                                # Get SID
                                $sidBytes = $result.Properties["objectSid"][0]
                                $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                                
                                # Get attribute value (handle multi-valued attributes)
                                $attributeValue = $null
                                if ($result.Properties.Contains($attr) -and $result.Properties[$attr].Count -gt 0) {
                                    if ($result.Properties[$attr].Count -eq 1) {
                                        $attributeValue = $result.Properties[$attr][0]
                                    } else {
                                        # Multi-valued attribute - store as array for proper JSON serialization
                                        $attributeValue = @($result.Properties[$attr])
                                    }
                                }
                                
                                # Skip if empty and IncludeEmpty not set
                                if (-not $IncludeEmpty) {
                                    if ($null -eq $attributeValue) {
                                        continue
                                    }
                                    if ($attributeValue -is [string] -and [string]::IsNullOrWhiteSpace($attributeValue)) {
                                        continue
                                    }
                                }
                                
                                # Get additional properties for logging
                                $samAccountName = if ($result.Properties.Contains("samAccountName")) {
                                    $result.Properties["samAccountName"][0]
                                } else {
                                    "Unknown"
                                }
                                
                                # Determine BloodHound kinds based on object type
                                $kinds = switch ($objType) {
                                    'User' { @("User", "Base") }
                                    'Computer' { @("Computer", "Base") }
                                    'Group' { @("Group", "Base") }
                                }
                                
                                # Check if this node already exists using O(1) hashtable lookup
                                if ($nodeIndex.ContainsKey($sid)) {
                                    # Add additional attribute to existing node
                                    $nodeIndex[$sid].properties[$attr] = $attributeValue
                                    Write-Verbose "Updated existing node for $objType`: $samAccountName - added $attr"
                                } else {
                                    # Create new OpenGraph node structure
                                    $node = @{
                                        id = $sid
                                        kinds = $kinds
                                        properties = @{
                                            objectid = $sid
                                        }
                                    }
                                    
                                    # Add attribute to properties
                                    $node.properties[$attr] = $attributeValue
                                    
                                    # Add to both index and list
                                    $nodeIndex[$sid] = $node
                                    [void]$allNodes.Add($node)
                                    Write-Verbose "Created new node for $objType`: $samAccountName - $attr"
                                }
                                
                            } catch {
                                Write-Warning "Error processing object: $_"
                                continue
                            }
                        }
                        
                    } finally {
                        # Ensure proper resource cleanup
                        if ($null -ne $results) {
                            $results.Dispose()
                        }
                        if ($null -ne $searcher) {
                            $searcher.Dispose()
                        }
                    }
                }
            }
            
            if ($allNodes.Count -eq 0) {
                Write-Warning "No objects were processed. No output file will be created."
                return
            }
            
            # Build the complete BloodHound OpenGraph JSON structure
            # Note: Only 'source_kind' is a standard metadata field per OpenGraph schema
            $openGraphData = @{
                metadata = @{
                    source_kind = $SourceKind
                }
                graph = @{
                    nodes = $allNodes
                    edges = @()
                }
            }
            
            # Export to JSON file without BOM for cross-platform compatibility
            Write-Verbose "Exporting data to $outputFile..."
            $jsonContent = $openGraphData | ConvertTo-Json -Depth 4 -Compress
            
            # Use .NET method for BOM-less UTF-8 output
            [System.IO.File]::WriteAllText($outputFile, $jsonContent, [System.Text.UTF8Encoding]::new($false))
            
            # Success summary
            Write-Host "`nExport completed successfully!" -ForegroundColor Green
            Write-Host "File: $outputFile" -ForegroundColor White
            Write-Host "Unique nodes exported: $($allNodes.Count)" -ForegroundColor White
            Write-Host "Attributes: $($Attribute -join ', ')" -ForegroundColor White
            Write-Host "Object types: $($ObjectType -join ', ')" -ForegroundColor White
            Write-Host "Source kind: $SourceKind" -ForegroundColor White
            
            # Return object if requested
            if ($PassThru) {
                return $openGraphData
            }
            
        } catch {
            throw "Failed to export custom attributes: $_"
        }
    }
    
    end {
        Write-Verbose "ADAttributeHound completed"
    }
}

# Example usage:
# ADAttributeHound -Attribute "extensionAttribute1" -ObjectType User
# ADAttributeHound -Attribute "CustomAttribute5" -ObjectType User,Computer -OutputPath "C:\exports" -Verbose
# ADAttributeHound -Attribute "info" -ObjectType User,Group -SearchBase "OU=IT,DC=contoso,DC=com"
# ADAttributeHound -Attribute "description" -ObjectType Computer -Server "DC01.contoso.com" -IncludeEmpty
# ADAttributeHound -Attribute "extensionAttribute1","extensionAttribute2","info" -ObjectType User
