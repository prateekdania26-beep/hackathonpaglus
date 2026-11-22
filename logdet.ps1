param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgsList
)

$env:Path = "C:\Users\$env:USERNAME\AppData\Local\Python\bin;" + $env:Path
& python -m log_detective.cli @ArgsList
