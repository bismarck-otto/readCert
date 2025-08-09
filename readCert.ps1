# bismarck-otto 2025-08-09 to calculate hash with readCert.ps1

# Copyright (c) 2025 Otto von Bismarck
# This project includes portions generated using OpenAI’s ChatGPT.
# All code is released under the MIT License.

# Show recipient certificate info from a certificate-encrypted PDF.
# Displays a MessageBox and copies serial(s) to the clipboard.
# ================================================================
#
# Nota Bene: Works in PowerShell 7.5.2 (not in 5.1)
#
# Create a shortcut in the SendTo folder:
# a) Press Win + R, type shell:sendto, press Enter.
# b) Right-click in the folder → New > Shortcut.
# c) Point it to/Type the location to the item:
#    pwsh.exe -ExecutionPolicy Bypass -File "C:\Path\To\readCert.ps1"
# d) Replace C:\Path\To\ with the actual path to your readCert.ps1 file.
# e) Name it something like 'Read PDF Recipient Certificates'.
# f) Right-click on the new shortcut → Properties > Run: 'Mimimized'.

# readCert.ps1

<#
.SYNOPSIS
  Show recipient certificate info from a certificate-encrypted PDF.
  Displays a MessageBox and copies serial(s) to the clipboard.

.PARAMETER Pdf
  Path to the PDF file (can be positional or -Pdf).

.PARAMETER QpdfPath
  Optional: path to qpdf.exe. If omitted, will try to find it on PATH.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Pdf,
  [Parameter(Position = 1)]
  [string]$QpdfPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Qpdf {
  param([string]$QpdfPath)
  if ($QpdfPath -and (Test-Path $QpdfPath)) { return (Resolve-Path $QpdfPath).Path }
  $cmd = Get-Command qpdf -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

function Expand-Pdf {
  param([string]$Pdf, [string]$QpdfExe)

  if ($QpdfExe) {
    $tmp = [IO.Path]::GetTempFileName()
    $out = [IO.Path]::ChangeExtension($tmp, ".pdf")
    Remove-Item $tmp -ErrorAction SilentlyContinue

    $qpdfOutput = & $QpdfExe --qdf --object-streams=disable --stream-data=uncompress --no-warn $Pdf $out 2>&1
    $exit = $LASTEXITCODE

    if ($exit -ne 0 -or -not (Test-Path $out)) {
      Write-Verbose ("qpdf failed (exit {0}): {1}" -f $exit, $qpdfOutput)
      Write-Verbose "Falling back to original PDF (raw scan mode)."
      return $Pdf
    }

    return $out
  }

  return $Pdf
}

function ConvertFrom-PdfAsciiHex {
  param([string]$s)
  $hex = ($s -replace '\s', '')
  if (($hex.Length % 2) -ne 0) { $hex += '0' }
  $bytes = New-Object byte[] ($hex.Length / 2)
  for ($i = 0; $i -lt $hex.Length; $i += 2) {
    $bytes[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
  }
  return $bytes
}

function ConvertFrom-PdfAscii85 {
  param([string]$s) # content between <~ and ~>

  # Simple ASCII85 decoder (no line breaks, handles 'z' shortcut)
  $out = New-Object System.Collections.Generic.List[byte]
  $i = 0
  while ($i -lt $s.Length) {
    $ch = $s[$i]
    if ($ch -eq 'z') {
      # 'z' represents 4 zero bytes
      $out.AddRange([byte[]](0, 0, 0, 0))
      $i++
      continue
    }

    # Collect up to 5 chars in a group
    $chunk = @()
    for ($j = 0; $j -lt 5 -and ($i + $j) -lt $s.Length; $j++) {
      $c = [int][char]$s[$i + $j]
      if ($c -lt 33 -or $c -gt 117) { break } # skip invalid/spaces
      $chunk += $c
    }
    if ($chunk.Count -eq 0) {
      $i++
      continue
    }

    # Remember how many chars we really had before padding
    $origCount = $chunk.Count

    # Pad with 'u' (117) to length 5 if incomplete
    while ($chunk.Count -lt 5) {
      $chunk += [int][char]'u'
    }

    # Decode base85 group to 32-bit number
    $val = 0
    foreach ($c in $chunk) {
      $val = $val * 85 + ($c - 33)
    }

    # Split into 4 bytes (big-endian)
    $bytes = [byte[]]@(
      ($val -shr 24) -band 0xFF,
      ($val -shr 16) -band 0xFF,
      ($val -shr 8) -band 0xFF,
      $val -band 0xFF
    )

    # If padded, drop the extra bytes:
    # origCount=2 → keep 1 byte, origCount=3 → keep 2, origCount=4 → keep 3
    if ($origCount -lt 5) {
      $bytes = $bytes[0..($origCount - 2)]
    }

    $out.AddRange($bytes)
    $i += $origCount
  }
  return $out.ToArray()
}

function ConvertFrom-PdfLiteralString {
  param([string]$s) # content between ( and )

  $bytes = New-Object System.Collections.Generic.List[byte]
  $i = 0
  while ($i -lt $s.Length) {
    $c = $s[$i]

    if ($c -ne '\') {
      $bytes.Add([byte][char]$c)
      $i++
      continue
    }

    # Backslash escape
    if ($i + 1 -ge $s.Length) { $bytes.Add(92); break }  # lone '\'

    $n = $s[$i + 1]

    switch ($n) {
      # Standard escapes
      'n' { $bytes.Add(10); $i += 2; continue }
      'r' { $bytes.Add(13); $i += 2; continue }
      't' { $bytes.Add(9); $i += 2; continue }
      'b' { $bytes.Add(8); $i += 2; continue }
      'f' { $bytes.Add(12); $i += 2; continue }
      '\' { $bytes.Add(92); $i += 2; continue }
      '(' { $bytes.Add(40); $i += 2; continue }
      ')' { $bytes.Add(41); $i += 2; continue }

      default {
        # Line continuation: backslash + CRLF / LF / CR => skip both
        if ($n -eq "`r" -or $n -eq "`n") {
          # If CRLF, skip both; else skip the single newline
          if ($n -eq "`r" -and ($i + 2) -lt $s.Length -and $s[$i + 2] -eq "`n") {
            $i += 3
          }
          else {
            $i += 2
          }
          continue
        }

        # Hex escape: \xHH (non-standard but common)
        if ($n -eq 'x' -and ($i + 3) -lt $s.Length -and
          $s[$i + 2] -match '[0-9A-Fa-f]' -and $s[$i + 3] -match '[0-9A-Fa-f]') {
          $hh = $s.Substring($i + 2, 2)
          $bytes.Add([Convert]::ToByte($hh, 16))
          $i += 4
          continue
        }

        # Octal escape: \ddd (up to 3 digits 0–7)
        $oct = ''
        for ($k = 1; $k -le 3 -and ($i + $k) -lt $s.Length; $k++) {
          if ($s[$i + $k] -notmatch '[0-7]') { break }
          $oct += $s[$i + $k]
        }
        if ($oct.Length -gt 0) {
          $bytes.Add([Convert]::ToByte($oct, 8))
          $i += (1 + $oct.Length)  # backslash + digits
          continue
        }

        # Unknown escape: emit following char literally
        $bytes.Add([byte][char]$n)
        $i += 2
      }
    } # switch
  } # while

  return $bytes.ToArray()
}

function Get-RecipientBlobs {
  param([string]$PdfPath)

  $bytes = [System.IO.File]::ReadAllBytes($PdfPath)
  $text = [Text.Encoding]::GetEncoding("ISO-8859-1").GetString($bytes)

  # Find /Encrypt reference in trailer
  $eref = [regex]::Match($text, '/Encrypt\s+(\d+)\s+(\d+)\s+R')
  if (-not $eref.Success) { return @() }
  $objNum = $eref.Groups[1].Value; $genNum = $eref.Groups[2].Value

  # Pull Encrypt object
  $objMatch = [regex]::Match(
    $text,
    [regex]::Escape("$objNum $genNum obj") + '(.*?)endobj',
    'Singleline'
  )
  if (-not $objMatch.Success) { return @() }
  $encDict = $objMatch.Groups[1].Value

  # Recipients array: direct [ ... ] or indirect n n R
  $arrBody = $null
  $direct = [regex]::Match($encDict, '/Recipients\s*\[(.*?)\]', 'Singleline')
  if ($direct.Success) {
    $arrBody = $direct.Groups[1].Value
  }
  else {
    $indRef = [regex]::Match($encDict, '/Recipients\s+(\d+)\s+(\d+)\s+R')
    if ($indRef.Success) {
      $arrNum = $indRef.Groups[1].Value; $arrGen = $indRef.Groups[2].Value
      $arrMatch = [regex]::Match(
        $text,
        [regex]::Escape("$arrNum $arrGen obj") + '(.*?)endobj',
        'Singleline'
      )
      if ($arrMatch.Success) { $arrBody = $arrMatch.Groups[1].Value }
    }
  }
  if (-not $arrBody) { return @() }

  # Return PSCustomObjects so byte[] never hits the pipeline raw
  $results = New-Object 'System.Collections.Generic.List[object]'

  foreach ($m in [regex]::Matches($arrBody, '<([0-9A-Fa-f\s]+)>')) {
    $results.Add([pscustomobject]@{ Bytes = (ConvertFrom-PdfAsciiHex  $m.Groups[1].Value); Kind = 'Hex' })
  }
  foreach ($m in [regex]::Matches($arrBody, '<~(.*?)~>', 'Singleline')) {
    $results.Add([pscustomobject]@{ Bytes = (ConvertFrom-PdfAscii85   $m.Groups[1].Value); Kind = 'Ascii85' })
  }
  foreach ($m in [regex]::Matches($arrBody, '\((.*?)\)', 'Singleline')) {
    $results.Add([pscustomobject]@{ Bytes = (ConvertFrom-PdfLiteralString $m.Groups[1].Value); Kind = 'Literal' })
  }

  return $results.ToArray()  # object[] of PSCustomObject { Bytes=byte[]; Kind=string }
}

function Get-RecipientIdentifiersFromCmsBytes {
  param([byte[]]$Bytes)

  Add-Type -AssemblyName System.Security
  $out = @()

  # 1) Try EnvelopedCms (most common for PDF recipients)
  try {
    $cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
    $cms.Decode($Bytes)

    foreach ($ri in @($cms.RecipientInfos)) {
      $type = $ri.RecipientIdentifier.Type  # IssuerAndSerialNumber or SubjectKeyIdentifier
      $issuer = $null; $serial = $null; $ski = $null

      if ($type -eq [System.Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber) {
        $iasn = [System.Security.Cryptography.Pkcs.SubjectIdentifier]$ri.RecipientIdentifier
        # .Value is IssuerAndSerialNumber
        $issuer = $iasn.Value.IssuerName.Name
        $serial = ($iasn.Value.SerialNumber -replace '\s', '').ToUpperInvariant()
      }
      elseif ($type -eq [System.Security.Cryptography.Pkcs.SubjectIdentifierType]::SubjectKeyIdentifier) {
        $ski = ($ri.RecipientIdentifier.Value -replace '\s', '').ToUpperInvariant()
      }

      $out += [pscustomobject]@{
        Type   = 'EnvelopedCms'
        Issuer = $issuer
        Serial = $serial
        SKI    = $ski
        Cert   = $null  # no cert necessarily embedded
      }
    }

    # Some producers also include certs in the CMS; add them if present
    if (@($cms.Certificates).Count -gt 0) {
      foreach ($c in @($cms.Certificates)) {
        $out += [pscustomobject]@{
          Type   = 'EmbeddedCert'
          Issuer = $c.Issuer
          Serial = ($c.SerialNumber -replace '\s', '').ToUpperInvariant()
          SKI    = ($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' } |
            ForEach-Object { [BitConverter]::ToString($_.RawData) -replace '-' }) # raw ext; optional
          Cert   = $c
        }
      }
    }

    if (@($out).Count -gt 0) { return $out }
  }
  catch {}

  # 2) Try SignedCms (some tools wrap data oddly)
  try {
    $scms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $scms.Decode($Bytes)
    if (@($scms.Certificates).Count -gt 0) {
      foreach ($c in @($scms.Certificates)) {
        $out += [pscustomobject]@{
          Type   = 'SignedCmsCert'
          Issuer = $c.Issuer
          Serial = ($c.SerialNumber -replace '\s', '').ToUpperInvariant()
          SKI    = ($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' } |
            ForEach-Object { [BitConverter]::ToString($_.RawData) -replace '-' })
          Cert   = $c
        }
      }
    }
  }
  catch {}

  return $out
}

function HexToBytes {
  param([string]$Hex)
  $hex = ($Hex -replace '\s', '')
  if (($hex.Length % 2) -ne 0) { $hex += '0' }  # PDF hex strings may be odd length; pad last nibble
  $len = $hex.Length
  $bytes = New-Object byte[] ($len / 2)
  for ($i = 0; $i -lt $len; $i += 2) {
    $bytes[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
  }
  return $bytes
}

function ConvertTo-NormalizedSerial([string]$s) { ($s -replace '\s', '').ToUpperInvariant() }

function Get-Unwrapped-DerOctetString {
  param([byte[]]$Data)
  if ($null -eq $Data -or $Data.Length -lt 2) { return $null }
  if ($Data[0] -ne 0x04) { return $null } # not OCTET STRING
  # parse DER length at Data[1..]
  $idx = 1
  $lenByte = $Data[$idx]; $idx++
  if (($lenByte -band 0x80) -eq 0) {
    $len = $lenByte
  }
  else {
    $n = $lenByte -band 0x7F
    if ($n -lt 1 -or $n -gt 4 -or $Data.Length -lt (1 + 1 + $n)) { return $null }
    $len = 0
    for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Data[$idx]; $idx++ }
  }
  if ($Data.Length -lt ($idx + $len)) { return $null }
  return $Data[$idx..($idx + $len - 1)]
}
function Get-DerTlvLength {
  param([byte[]]$Data)
  if ($null -eq $Data -or $Data.Length -lt 2) { return 0 }
  $idx = 0
  $tag = $Data[$idx]; $idx++
  # we only care about SEQUENCE (0x30) here; bail if not
  if ($tag -ne 0x30) { return 0 }
  $lenByte = $Data[$idx]; $idx++
  if (($lenByte -band 0x80) -eq 0) {
    $len = $lenByte
    return 1 + 1 + $len       # tag + len + value
  }
  else {
    $n = $lenByte -band 0x7F
    if ($n -lt 1 -or $n -gt 4 -or $Data.Length -lt (2 + $n)) { return 0 }
    $len = 0
    for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Data[$idx]; $idx++ }
    return 1 + 1 + $n + $len   # tag + lenlen + lenbytes + value
  }
}

function Get-RecipientFromCertutilText {
  param([string]$Text)

  $issuerLines = @()
  $serial = $null

  $lines = $Text -split "`r?`n"

  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]

    # Grab human-readable RDN values (the parts in quotes on certutil's dump)
    if ($line -match ';\s*"(.*)"\s*$') {
      $issuerLines += $matches[1]
    }

    # Serial: look for INTEGER then slurp hex bytes on the following lines
    if ($line -match ';\s*INTEGER\s*\(') {
      $hex = ""
      for ($j = 1; $j -le 3 -and ($i + $j) -lt $lines.Count; $j++) {
        if ($lines[$i + $j] -match '^\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+)\s*$') {
          $hex += " " + $matches[1]
        }
        else { break }
      }
      if ($hex) {
        $serial = ($hex -split '\s+' | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }) -join ''
        $serial = $serial -replace '^(00)+', ''  # drop leading 00s
        break
      }
    }
  }

  if ($issuerLines.Count -eq 0 -and -not $serial) { return @() }

  # Reverse issuer order: certutil prints C,O,CN... we want CN,O,C...
  $issuerText = ($issuerLines -join ', ')
  $issuerParts = $issuerText -split '\s*,\s*'
  [array]::Reverse($issuerParts)
  $issuer = ($issuerParts -join ', ')

  , ([pscustomobject]@{
      Type   = 'ParsedCertutil'
      Issuer = $issuer
      Serial = $serial
      SKI    = $null
      Cert   = $null
    })
}

# Load personal store for matching
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "My", "CurrentUser"
$store.Open("ReadOnly")
$myBySerial = @{}
foreach ($c in $store.Certificates) { $myBySerial[(ConvertTo-NormalizedSerial $c.SerialNumber)] = $c }
$store.Close()

$qpdfExe = Resolve-Qpdf -QpdfPath $QpdfPath
if (-not $qpdfExe) {
  Write-Verbose "qpdf not found — install it for reliable results."
  Write-Verbose "Install qpdf from official source: https://qpdf.sourceforge.io"
}

$expanded = $null
try {
  $copyText = $null

  $expanded = Expand-Pdf -Pdf $Pdf -QpdfExe $qpdfExe

  # Get blobs from expanded
  $blobObjs = Get-RecipientBlobs -PdfPath $expanded

  # Verbose: count + types (no pipeline to avoid byte[] flattening)
  Write-Verbose ("Recipient blob objects after -PdfPath `$expanded: {0}" -f (@($blobObjs).Count))
  $types = New-Object System.Collections.Generic.List[string]
  foreach ($o in @($blobObjs)) { $types.Add($o.GetType().FullName) }
  Write-Verbose ("Recipient blob object types: " + ($types -join ', '))

  # Fallback to original if none found
  if (@($blobObjs).Count -eq 0) {
    $blobObjs = Get-RecipientBlobs -PdfPath $Pdf
    Write-Verbose ("Recipient blob objects after -PdfPath `$Pdf: {0}" -f (@($blobObjs).Count))
    $types = New-Object System.Collections.Generic.List[string]
    foreach ($o in @($blobObjs)) { $types.Add($o.GetType().FullName) }
    Write-Verbose ("Recipient blob object types: " + ($types -join ', '))
  }

  if (@($blobObjs).Count -eq 0) {
    Write-Verbose "Couldn't locate any decodable /Recipients entries."
    return
  }

  # Extract byte[] WITHOUT using the pipeline (prevents flattening)
  $blobs = New-Object 'System.Collections.Generic.List[byte[]]'
  foreach ($o in @($blobObjs)) {
    if ($null -eq $o) { continue }

    # Case 1: raw byte[]
    if ($o -is [byte[]]) {
      $blobs.Add($o)
      continue
    }

    # Case 2: PSCustomObject with .Bytes
    $p = $o.PSObject.Properties.Match('Bytes')
    if ($p.Count -gt 0) {
      $val = $o.Bytes
      $valType = if ($null -eq $val) { '<null>' } else { $val.GetType().FullName }
      Write-Verbose ("Found .Bytes property of type: {0}" -f $valType)

      if ($val -is [byte[]]) {
        $blobs.Add($val)
        continue
      }

      # If it's IList<byte> (e.g., List[byte])
      if ($val -is [System.Collections.Generic.IList[byte]]) {
        $blobs.Add([byte[]]$val.ToArray())
        continue
      }

      # If it's object[] of byte (common when something boxed it oddly)
      if ($val -is [object[]] -and $val.Length -gt 0 -and $val[0] -is [byte]) {
        $tmp = New-Object byte[] ($val.Length)
        for ($i = 0; $i -lt $val.Length; $i++) { $tmp[$i] = [byte]$val[$i] }
        $blobs.Add($tmp)
        continue
      }

      # If it's a string, try to decode using Kind
      if ($val -is [string]) {
        $kind = ($o.PSObject.Properties['Kind']?.Value)
        Write-Verbose ("Bytes is string; Kind={0}" -f $kind)
        try {
          switch ($kind) {
            'Hex' { $tmp = ConvertFrom-PdfAsciiHex $val }
            'Ascii85' { $tmp = ConvertFrom-PdfAscii85 $val }
            'Literal' { $tmp = ConvertFrom-PdfLiteralString $val }
            default { $tmp = $null }
          }
          if ($tmp -is [byte[]] -and $tmp.Length -gt 0) { $blobs.Add($tmp); continue }
        }
        catch {}
      }

      # Last resort verbose dump of property names/types for debugging
      Write-Verbose ("Skipping PSCustomObject; properties:")
      foreach ($pp in $o.PSObject.Properties) {
        $tn = if ($null -eq $pp.Value) { '<null>' } else { $pp.Value.GetType().FullName }
        Write-Verbose ("  {0} : {1}" -f $pp.Name, $tn)
      }
      continue
    }

    Write-Verbose ("Skipping non-blob object: {0}" -f $o.GetType().FullName)
  }

  $recipientBlobs = $blobs.ToArray()
  Write-Verbose ("Recipient blobs (byte[]) after extraction: {0}" -f $recipientBlobs.Length)
  if ($recipientBlobs.Length -eq 0) { Write-Verbose "No byte[] blobs to parse."; return }

  # OPTIONAL: dump first blob to file and peek with certutil
  if ($recipientBlobs.Length -gt 0) {
    $tmpBin = [IO.Path]::Combine([IO.Path]::GetTempPath(), "pdf-recipient-blob.bin")
    [IO.File]::WriteAllBytes($tmpBin, $recipientBlobs[0])
    Write-Verbose ("Wrote first blob to: {0}" -f $tmpBin)
    try {
      $asn = certutil -asn $tmpBin 2>&1
      Write-Verbose ($asn -join [Environment]::NewLine)
    }
    catch {
      Write-Verbose "certutil -asn not available or failed."
    }
  }

  # Diagnostics: length + first 32 bytes
  $first = $recipientBlobs[0]
  Write-Verbose ("Blob[0] length: {0}" -f $first.Length)
  Write-Verbose ("Blob[0] head: {0}" -f ([BitConverter]::ToString($first[0..([Math]::Min($first.Length - 1, 31))])))

  # Decode CMS recipient identifiers
  $foundCerts = New-Object System.Collections.Generic.List[Object]

  foreach ($bytes in $recipientBlobs) {

    # Log header
    Write-Verbose ("Blob length: {0}" -f $bytes.Length)
    Write-Verbose ("Blob head: {0}" -f ([BitConverter]::ToString($bytes[0..([Math]::Min($bytes.Length - 1, 31))])))

    # If it starts with OCTET STRING (0x04), try unwrapping once
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x04) {
      $inner = Get-Unwrapped-DerOctetString -Data $bytes
      if ($inner -and $inner.Length -gt 0) {
        Write-Verbose "Unwrapped outer DER OCTET STRING."
        $bytes = $inner
        Write-Verbose ("Inner head: {0}" -f ([BitConverter]::ToString($bytes[0..([Math]::Min($bytes.Length - 1, 31))])))
      }
    }

    # Heuristic: CMS is usually a SEQUENCE (0x30)
    if ($bytes.Length -gt 0 -and $bytes[0] -ne 0x30) {
      Write-Verbose "Not starting with ASN.1 SEQUENCE (0x30); still attempting CMS decode."
    }

    # Trim trailing junk if length field doesn't match total bytes
    $tlvLen = Get-DerTlvLength -Data $bytes
    if ($tlvLen -gt 0 -and $tlvLen -lt $bytes.Length) {
      Write-Verbose ("Trimming trailing {0} byte(s) after DER object." -f ($bytes.Length - $tlvLen))
      $bytes = $bytes[0..($tlvLen - 1)]
    }
  
    $ids = Get-RecipientIdentifiersFromCmsBytes -Bytes $bytes
    if (-not $ids -or @($ids).Count -eq 0) {
      # Fallback: parse via certutil -asn
      $tmpBin = [IO.Path]::GetTempFileName()
      [IO.File]::WriteAllBytes($tmpBin, $bytes)
      try {
        $ctext = certutil -asn $tmpBin 2>&1 | Out-String
        if ($ctext -match 'Enveloped' -or $ctext -match 'PKCS 7') {
          $parsed = Get-RecipientFromCertutilText -Text $ctext
          if ($parsed) {
            Write-Verbose "Fallback certutil parse found $(@($parsed).Count) recipient(s)."
            foreach ($p in $parsed) { $null = $foundCerts.Add($p) }
          }
        }
      }
      finally {
        Remove-Item $tmpBin -ErrorAction SilentlyContinue
      }
    }
    else {
      foreach ($id in @($ids)) { $null = $foundCerts.Add($id) }
    }
  }

  if ($foundCerts.Count -eq 0) {
    Write-Verbose "Found recipient data but couldn't decode any X.509 certificates."
    return
  }

  # Build output
  $lines = @()
  $serialsToCopy = New-Object System.Collections.Generic.List[string]
  $idx = 1

  foreach ($r in $foundCerts) {
    $issuer = $r.Issuer
    $serial = $r.Serial
    if ($serial) { $serial = ConvertTo-NormalizedSerial $serial }
    $ski = $r.SKI

    $match = $false
    if ($serial) {
      $match = $myBySerial.ContainsKey($serial)
      if ($match) { $serialsToCopy.Add($serial) }
    }

    $lines += @(
      "Recipient #$idx ($($r.Type))",
      ($(if ($issuer) { "  Issuer : $issuer" })),
      ($(if ($serial) { "  Serial : $serial" })),
      ($(if ($ski) { "  SKI    : $ski" })),
      ($(if ($match) { "  -> matches your Personal store" })),
      ""
    ) | Where-Object { $null -ne $_ }

    $idx++
  }

  # Show MessageBox
  if ($foundCerts.Count -gt 0) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
      ($lines -join [Environment]::NewLine),
      "PDF Recipient Certificates",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
  }

  # Clipboard: prefer serials; fall back to SKIs
  if ($serialsToCopy.Count -eq 0) {
    $skis = $foundCerts | Where-Object { $_.SKI } | Select-Object -ExpandProperty SKI -Unique
    if ($skis) {
      $copyText = ($skis -join [Environment]::NewLine)
      $copyText | clip.exe
    }
  }
  else {
    $copyText = (($serialsToCopy | Select-Object -Unique) -join [Environment]::NewLine)
    $copyText | clip.exe
  }

  if ($copyText) { Write-Host "Copied identifier(s) to clipboard:`n$copyText" }

}
finally {
  if ($expanded -and $expanded -ne $Pdf -and (Test-Path $expanded)) {
    Remove-Item $expanded -ErrorAction SilentlyContinue
  }
}
