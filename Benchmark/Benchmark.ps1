# Enable Windows Forms for MessageBox
Add-Type -AssemblyName System.Windows.Forms

# CPU Benchmark
function Test-CPU {
    $start = Get-Date
    $maxIterations = 10000
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $result = $i * 2 + 1 - $i
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Integer Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $intTime = (Get-Date) - $start

    $start = Get-Date
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $result = [math]::sqrt($i) * [math]::PI
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Floating Point Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $floatTime = (Get-Date) - $start

    $cpuScore = 1 / ($intTime.TotalSeconds + $floatTime.TotalSeconds)
    return [math]::Round($cpuScore * 5000, 2)
}

# Memory Benchmark
function Test-Memory {
    $maxIterations = 10000
    $array = @()
    
    # Memory Write Test
    $start = Get-Date
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $array += Get-Random -Maximum 10000
        Write-Progress -Activity "Memory Benchmark" -Status "Writing to Memory..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $writeTime = (Get-Date) - $start

    # Memory Read Test
    $start = Get-Date
    $sum = 0
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $sum += $array[$i]
        Write-Progress -Activity "Memory Benchmark" -Status "Reading from Memory..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $readTime = (Get-Date) - $start

    $memoryWriteScore = 1 / $writeTime.TotalSeconds
    $memoryReadScore = 1 / $readTime.TotalSeconds
    return [math]::Round($memoryWriteScore * 2500, 2), [math]::Round($memoryReadScore * 2500, 2)
}

# Disk Benchmark
function Test-Disk {
    $directory = "$env:USERPROFILE\Documents"  # Use user-accessible directory
    if (-not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    $filePath = "$directory\benchmark_testfile.txt"
    $content = "0" * 1024 * 1024 # 1 MB data

    # Ensure file is created
    $start = Get-Date
    try {
        Set-Content -Path $filePath -Value $content -Force
    } catch {
        return "Disk Write Error"
    }
    Start-Sleep -Milliseconds 100  # Wait to ensure file is written
    $writeTime = (Get-Date) - $start

    # Check if file exists before reading
    if (Test-Path -Path $filePath) {
        $start = Get-Date
        $data = Get-Content -Path $filePath -Raw
        $readTime = (Get-Date) - $start
        Remove-Item -Path $filePath -Force
    } else {
        return "Disk Read Error"
    }

    $diskScore = 1 / ($writeTime.TotalSeconds + $readTime.TotalSeconds)
    return [math]::Round($diskScore * 10, 2)
}

# Graphics Benchmark
function Test-Graphics {
    $start = Get-Date
    $maxFrames = 1000
    for ($i = 0; $i -lt $maxFrames; $i++) {
        Start-Sleep -Milliseconds 1
        Write-Progress -Activity "Graphics Benchmark" -Status "Rendering Frames..." -PercentComplete (($i / $maxFrames) * 100)
    }
    $renderTime = (Get-Date) - $start

    $graphicsScore = 1 / $renderTime.TotalSeconds
    return [math]::Round($graphicsScore * 1000, 2)
}

# Main Function
function Run-Benchmark {
    # Run Benchmark
    $cpuScore = Test-CPU
    $memoryWriteScore, $memoryReadScore = Test-Memory
    $diskScore = Test-Disk
    $graphicsScore = Test-Graphics

    # Display Results in MessageBox
    $results = @"
CPU Score: $cpuScore
Memory Write Score: $memoryWriteScore
Memory Read Score: $memoryReadScore
Disk Score: $diskScore
Graphics Score: $graphicsScore
"@

    [System.Windows.Forms.MessageBox]::Show($results, "Benchmark Results", "OK", "Information")
}

# Run the benchmark
Run-Benchmark

