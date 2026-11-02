$ErrorActionPreference='Stop'
$errorsFound=0
Get-ChildItem (Join-Path $PSScriptRoot '..') -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1' } | ForEach-Object {
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
 foreach($e in $errors){Write-Output ($_.Name+': '+$e.Message);$errorsFound++}
}
if($errorsFound){throw 'PowerShell parse errors'}
Write-Output 'PowerShell parse clean'
