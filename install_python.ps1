# portable Python 3.11 installer and bootstrapper for NetGuard

$workspace = "d:\Netcat"
$pythonDir = "$workspace\python311"
$zipPath = "$workspace\python-embed.zip"
$pipScriptPath = "$pythonDir\get-pip.py"

Write-Host "Creating python directory..."
if (-not (Test-Path $pythonDir)) {
    New-Item -ItemType Directory -Path $pythonDir
}

Write-Host "Downloading Python 3.11.9 embeddable zip..."
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip" -OutFile $zipPath

Write-Host "Extracting Python..."
Expand-Archive -Path $zipPath -DestinationPath $pythonDir -Force
Remove-Item $zipPath

Write-Host "Configuring Python path to enable site-packages..."
# In pythonxx._pth, we need to uncomment "import site" so pip and installed modules can be found
$pthFile = "$pythonDir\python311._pth"
if (Test-Path $pthFile) {
    $content = Get-Content $pthFile
    $newContent = @()
    foreach ($line in $content) {
        if ($line -eq "#import site") {
            $newContent += "import site"
        } else {
            $newContent += $line
        }
    }
    # Also add the local directory to search path
    $newContent += "."
    Set-Content -Path $pthFile -Value $newContent
}

Write-Host "Downloading get-pip.py..."
Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $pipScriptPath

Write-Host "Bootstrapping pip..."
# Run the portable python to install pip
& "$pythonDir\python.exe" $pipScriptPath

Write-Host "Removing get-pip.py script..."
if (Test-Path $pipScriptPath) {
    Remove-Item $pipScriptPath
}

Write-Host "Installing dependencies..."
& "$pythonDir\python.exe" -m pip install --upgrade pip
& "$pythonDir\python.exe" -m pip install pyqt6 pyqtgraph scapy pydivert

Write-Host "Python environment setup complete!"
