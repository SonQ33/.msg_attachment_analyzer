function Expand-MsgAttachment
{
    [CmdletBinding()]

    Param
    (
        [Parameter(ParameterSetName="Path", Position=0, Mandatory=$True)]
        [String]$Path,

        [Parameter(ParameterSetName="LiteralPath", Mandatory=$True)]
        [String]$LiteralPath,

        [Parameter(ParameterSetName="FileInfo", Mandatory=$True, ValueFromPipeline=$True)]
        [System.IO.FileInfo]$Item
    )

    Begin
    {
        # Load application
        Write-Verbose "Loading Microsoft Outlook..."
        $outlook = New-Object -ComObject Outlook.Application
    }

    Process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            "Path"        { $files = Get-ChildItem -Path $Path }
            "LiteralPath" { $files = Get-ChildItem -LiteralPath $LiteralPath }
            "FileInfo"    { $files = $Item }
        }

        $files | % {
            # Work out file names
            $msgFn = $_.FullName
            # Skip non-.msg files
            if ($msgFn -notlike "*.msg")
            {
                Write-Verbose "Skipping $_ (not an .msg file)..."
                return
            }

            # Extract message body
            Write-Verbose "Extracting attachments from $_..."
            $msg = $outlook.CreateItemFromTemplate($msgFn)
            $new_folder = $msgFn -replace '\.msg$', ""
            $new_folder = $new_folder -replace 'ANTIPHISH', ''
            $new_folder = $new_folder -replace "📢EXTERNAL❗",""
            $new_folder = $new_folder -replace "KSMG обнаружен макрос",""
            $new_folder = $new_folder -replace "\[",""
            $new_folder = $new_folder -replace "\]",""

            $new_folder = $new_folder.Trim()
                        
            New-Item -Path "$new_folder" -ItemType Directory | Out-Null
            $count_error = 0

            $msg.Attachments | % {

                # Work out attachment file name (decoding )
                $file_att_name = $_.FileName
                $file_att_name = $file_att_name | ConvertTo-Encoding "windows-1251" "utf-16"
                $file_att_name = $file_att_name -replace [char]0, ''
                $att_full_path = "$new_folder\$file_att_name"


                $check_error = 0
                $ext = $file_att_name.split('.')[-1]
                
                # Save attachment
                Write-Verbose "Saving $att_full_path..."
                try
                {
                    if ($ext -ne "jpg" -or $ext -ne "png")
                    {
                        $_.SaveAsFile($att_full_path)
                    }
              
                }
                catch
                {
                    $ext = $file_att_name.split('.')[-1]
                    $att_full_path = "$new_folder\$count_error.$ext"
                    $count_error++
                    $check_error = 1
                }

                if ($check_error)
                {
                    try
                    {
                        if ($ext -ne "jpg" -or $ext -ne "png")
                        {
                            $_.SaveAsFile($att_full_path)
                        }
                    }
                    catch
                    {
                        echo "Mne 13 let i ya v tilte"
                        echo "$att_full_path"
                        $count_error++
                    }
                }
            }
        }
        $msg.Close(1)
        $msg = $null
        $outlook.Quit()
    }

    End
    {
        Write-Verbose "Done."
    }
}

function ConvertTo-Encoding ([string]$From, [string]$To){
	Begin
    {
		$encFrom = [System.Text.Encoding]::GetEncoding($from)
		$encTo = [System.Text.Encoding]::GetEncoding($to)
	}
	Process
    {
		$bytes = $encTo.GetBytes($_)
		$bytes = [System.Text.Encoding]::Convert($encFrom, $encTo, $bytes)
		$encTo.GetString($bytes)
	}
}

function Analysis-OleTools ($path)
{
    Begin
    {
        $file_path = $path
    }
    Process
    {
        $buffer = python "C:\Python27\Lib\site-packages\oletools\oleid.py" "$path"
        $mal_check = 0

        foreach($line in $buffer)
        {
            switch($line)
            {
                {$PSItem.StartsWith("Encrypted")}
                {
                    $cur_res = $PSItem.split("|")[1]
                    if(-not ($cur_res.StartsWith("False")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("VBA")}
                {
                    $cur_res = $PSItem.split("|")[1]
                    if(-not ($cur_res.StartsWith("No")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("XLM")}
                {
                    $cur_res = $PSItem.split("|")[1]
                    if(-not ($cur_res.StartsWith("No")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("External")}
                {
                    $cur_res = $PSItem.split("|")[1]
                    if(-not ($cur_res.StartsWith("0")))
                    {
                        
                        $mal_check++
                    }
                }
            }
        }
        if($mal_check -gt 0)
        {
            return "Malicious"
        }
        else
        {
            return "Not malicious"
        }
    }
}

function Analysis-PDF ($path)
{
    Begin
    {
        $file_path = $path
    }
    Process
    {
        $buffer = python "C:\Program Files (x86)\pdfid\pdfid.py" "$path"
        $mal_check = 0
        foreach($line in $buffer)
        {
            $line = $line.Trim()
            switch($line)
            {
                {$PSItem.StartsWith("/Encrypt")}
                {
                    $cur_res = $PSItem.split(' ')[-1]
                    if(-not ($cur_res.StartsWith("0")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("/JavaScript")}
                {
                    $cur_res = $PSItem.split(' ')[-1]
                    if(-not ($cur_res.StartsWith("0")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("/OpenAction")}
                {
                    $cur_res = $PSItem.split(' ')[-1]
                    if(-not ($cur_res.StartsWith("0")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("/Launch")}
                {
                    $cur_res = $PSItem.split(' ')[-1]
                    if(-not ($cur_res.StartsWith("0")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("/EmbeddedFile")}
                {
                    $cur_res = $PSItem.split(' ')[-1]
                    if(-not ($cur_res.StartsWith("0")))
                    {
                        $mal_check++
                    }
                }
                {$PSItem.StartsWith("/URI")}
                {
                    $cur_res = $PSItem.split(' ')[-1]
                    if(-not ($cur_res.StartsWith("0")))
                    {
                        $mal_check++
                    }
                }
            }
        }

        if($mal_check -gt 0)
        {
            return "Malicious"
        }
        else
        {
            return "Not malicious"
        }
    }
}


Expand-MsgAttachment *

Get-Process -Name *outlook* | Stop-Process -force

$for_report = @()

$all_directory = Get-ChildItem -Directory

foreach($current_directory in $all_directory)
{
    $report = ""
    $all_files = Get-ChildItem -File $current_directory.FullName

    if(".zip" -in $all_files.Extension -or ".rar" -in $all_files.Extension -or ".7z" -in $all_files.Extension)
    {
        echo "Archive: "
    }

    foreach($cur_file in $all_files)
    {
        $report_str = ""
        $full_file = $cur_file.FullName

        $buffer = Get-FileHash $full_file| Select Hash
        $buffer = $buffer.Hash
        $file_name = $cur_file.FullName
        $report= "$file_name^ $buffer^"

        $result= ""
        switch ($cur_file.Extension)
        {
            {$PSItem.Contains("xls") -or $PSItem.Contains("doc") -or $PSItem.Contains("ppt") -or $PSItem.Contains("PPT") -or $PSItem.Contains("XLS") -or $PSItem.Contains("DOC")}
            {
               $result = Analysis-OleTools $file_name
            }
            {$PSItem.Contains("pdf") -or $PSItem.Contains("PDF")}
            {
                $result = Analysis-PDF $file_name
            }
            {$PSItem.Contains("exe")}
            {
                $result = "Executable"
            }
            default
            {
                $result = $PSItem
            }
        }
        $report+= "$result^"
        $report+=$current_directory.FullName
        $for_report+=$report
    }
}

$List = New-Object System.Collections.ArrayList

$for_report | ForEach-Object {
	$buf_arr = $_.split("^")
	$table = [ordered]@{
		Name = $buf_arr[0]
		Hash = $buf_arr[1]
		Result = $buf_arr[2]
	}
	[void]$List.Add(([pscustomobject]$table))
}

$List | Format-List | Out-File -FilePath .\Report.txt