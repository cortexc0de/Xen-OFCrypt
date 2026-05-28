$dllPath = "$PSScriptRoot\sc_test.dll"
$binPath = "$PSScriptRoot\sc_test.bin"

if (-not (Test-Path $dllPath)) {
    Write-Host "ERROR: sc_test.dll not found"
    exit 1
}

$dll = [System.IO.File]::ReadAllBytes($dllPath)
$peOff = [BitConverter]::ToInt32($dll, 0x3C)
$numSec = [BitConverter]::ToUInt16($dll, $peOff + 6)
$optHdrSize = [BitConverter]::ToUInt16($dll, $peOff + 20)
$secHdrOff = $peOff + 4 + 20 + $optHdrSize

Write-Host "PE offset=$peOff sections=$numSec optHdrSize=$optHdrSize"

for ($i = 0; $i -lt $numSec; $i++) {
    $off = $secHdrOff + $i * 40
    $name = [Text.Encoding]::ASCII.GetString($dll, $off, 8).TrimEnd([char]0)
    $virtSize = [BitConverter]::ToUInt32($dll, $off + 8)
    $rawSize = [BitConverter]::ToUInt32($dll, $off + 16)
    $rawOff = [BitConverter]::ToUInt32($dll, $off + 20)
    Write-Host "  Section: $name virtSize=$virtSize rawSize=$rawSize rawOff=$rawOff"

    if ($name -eq '.text') {
        $code = New-Object byte[] $rawSize
        [Array]::Copy($dll, $rawOff, $code, 0, $rawSize)
        [System.IO.File]::WriteAllBytes($binPath, $code)
        Write-Host "  EXTRACTED $rawSize bytes to sc_test.bin"
    }
}
