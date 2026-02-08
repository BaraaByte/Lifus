#!/usr/bin/env python3
import os
import sys
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

# ========== CORE UTILITIES ==========
def run_cmd(cmd: str, sudo: bool = False) -> bool:
    """Run command and return success status"""
    try:
        if sudo:
            cmd = f"sudo {cmd}"
        result = subprocess.run(cmd, shell=True, check=True, 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {cmd}")
        return False

def get_output(cmd: str) -> str:
    """Get command output"""
    try:
        result = subprocess.run(cmd, shell=True, check=True, 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                              text=True)
        return result.stdout.strip()
    except:
        return ""

# ========== DEVICE DETECTION ==========
class USBDevice:
    def __init__(self, path: str, model: str, size: int, removable: bool):
        self.path = path
        self.model = model
        self.size = size
        self.removable = removable
    
    def __str__(self):
        gb = self.size / (1024**3)
        return f"{self.path} ({self.model}) - {gb:.1f}GB"

def get_usb_devices() -> List[USBDevice]:
    """Get list of USB devices"""
    devices = []
    
    # Use lsblk to get device info
    cmd = "lsblk -J -o NAME,PATH,MODEL,SIZE,TYPE,RM,MOUNTPOINT"
    try:
        output = get_output(cmd)
        data = json.loads(output)
        
        for device in data.get("blockdevices", []):
            if device.get("type") == "disk" and device.get("rm") == 1:
                # Skip if mounted as root or system
                is_system = False
                for child in device.get("children", []):
                    if child.get("mountpoint") in ["/", "/boot", "/home"]:
                        is_system = True
                        break
                
                if not is_system:
                    size_str = device.get("size", "0")
                    size = parse_size(size_str)
                    devices.append(USBDevice(
                        path=device.get("path"),
                        model=device.get("model", "Unknown"),
                        size=size,
                        removable=True
                    ))
    except:
        # Fallback to sysfs
        for dev in Path("/sys/block").iterdir():
            if dev.name.startswith(("sd", "nvme")):
                removable = (dev / "removable").read_text().strip() == "1"
                if removable:
                    size_path = dev / "size"
                    if size_path.exists():
                        sectors = int(size_path.read_text().strip())
                        size = sectors * 512
                        model = "Unknown"
                        model_path = dev / "device" / "model"
                        if model_path.exists():
                            model = model_path.read_text().strip()
                        
                        devices.append(USBDevice(
                            path=f"/dev/{dev.name}",
                            model=model,
                            size=size,
                            removable=True
                        ))
    
    return devices

def parse_size(size_str: str) -> int:
    """Parse human readable size to bytes"""
    units = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    size_str = size_str.upper().replace(" ", "")
    
    for unit, multiplier in units.items():
        if size_str.endswith(unit):
            num = float(size_str[:-len(unit)])
            return int(num * multiplier)
    
    # No unit, assume bytes
    return int(float(size_str))

# ========== ISO DETECTION ==========
def detect_iso_type(iso_path: str) -> str:
    """Detect if ISO is Windows or Linux"""
    if not os.path.exists(iso_path):
        return "not_found"
    
    # Check file signature
    check_cmds = [
        f"file -b '{iso_path}' | grep -i windows",
        f"strings '{iso_path}' | grep -i 'microsoft' | head -1",
        f"strings '{iso_path}' | grep -i 'bootmgr' | head -1"
    ]
    
    for cmd in check_cmds:
        if get_output(cmd):
            return "windows"
    
    # Check for Linux signatures
    linux_cmds = [
        f"file -b '{iso_path}' | grep -i 'iso 9660'",
        f"strings '{iso_path}' | grep -i 'isolinux' | head -1",
        f"strings '{iso_path}' | grep -i 'grub' | head -1"
    ]
    
    for cmd in linux_cmds:
        if get_output(cmd):
            return "linux"
    
    return "unknown"

# ========== WRITERS ==========
class USBWriter:
    def __init__(self):
        self.check_dependencies()
    
    def check_dependencies(self):
        """Check required tools"""
        tools = ["lsblk", "parted", "dd", "sync"]
        for tool in tools:
            if not shutil.which(tool):
                print(f"[ERROR] Required tool missing: {tool}")
                sys.exit(1)
    
    def unmount_device(self, device: str):
        """Unmount all partitions on device"""
        print(f"[INFO] Unmounting {device}")
        run_cmd(f"umount {device}* 2>/dev/null", sudo=True)
    
    def write_linux_iso(self, iso_path: str, device: str) -> bool:
        """Write Linux ISO using dd"""
        print(f"[INFO] Writing Linux ISO to {device}")
        
        # Unmount first
        self.unmount_device(device)
        
        # Write with dd
        cmd = f"dd if='{iso_path}' of='{device}' bs=4M status=progress conv=fsync"
        print(f"[EXEC] {cmd}")
        
        if run_cmd(cmd, sudo=True):
            run_cmd("sync", sudo=True)
            print(f"[SUCCESS] Linux USB created on {device}")
            return True
        
        return False
    
    def write_with_ventoy(self, iso_path: str, device: str) -> bool:
        """Write using Ventoy (best for Windows)"""
        print(f"[INFO] Using Ventoy for {device}")
        
        # Check if Ventoy exists
        ventoy_path = shutil.which("ventoy")
        if not ventoy_path:
            print("[ERROR] Ventoy not installed. Install with:")
            print("  wget https://github.com/ventoy/Ventoy/releases/latest/download/ventoy-1.0.97-linux.tar.gz")
            print("  tar -xzf ventoy-*.tar.gz")
            print("  sudo cp ventoy*/ventoy /usr/local/bin/")
            return False
        
        # Unmount device
        self.unmount_device(device)
        
        # Install Ventoy to USB
        print(f"[INFO] Installing Ventoy to {device}")
        if not run_cmd(f"{ventoy_path} -i {device}", sudo=True):
            print("[ERROR] Failed to install Ventoy")
            return False
        
        # Wait for device to be ready
        run_cmd("sleep 2", sudo=False)
        
        # Find Ventoy partition (usually first partition)
        ventoy_part = f"{device}1"
        if not os.path.exists(ventoy_part):
            ventoy_part = f"{device}p1"
        
        # Create mount point
        with tempfile.TemporaryDirectory() as mount_point:
            # Mount Ventoy partition
            if run_cmd(f"mount {ventoy_part} {mount_point}", sudo=True):
                # Copy ISO
                dest = os.path.join(mount_point, os.path.basename(iso_path))
                print(f"[INFO] Copying ISO to {dest}")
                shutil.copy2(iso_path, dest)
                
                # Unmount
                run_cmd(f"umount {mount_point}", sudo=True)
                print(f"[SUCCESS] Windows/Linux USB created with Ventoy on {device}")
                return True
        
        return False

# ========== MAIN WORKFLOW ==========
def main():
    if len(sys.argv) < 2:
        print("USAGE:")
        print("  ./usb_tool.py list")
        print("  ./usb_tool.py create <iso_file> [device]")
        print("  ./usb_tool.py create-win <iso_file> [device]")
        print("  ./usb_tool.py create-linux <iso_file> [device]")
        sys.exit(1)
    
    command = sys.argv[1]
    writer = USBWriter()
    
    if command == "list":
        devices = get_usb_devices()
        if not devices:
            print("[INFO] No USB devices found")
        else:
            print("Available USB devices:")
            for i, dev in enumerate(devices, 1):
                print(f"  {i}. {dev}")
    
    elif command == "create":
        if len(sys.argv) < 3:
            print("[ERROR] Need ISO file")
            sys.exit(1)
        
        iso_path = sys.argv[2]
        device = sys.argv[3] if len(sys.argv) > 3 else None
        
        # Auto-detect ISO type
        iso_type = detect_iso_type(iso_path)
        print(f"[INFO] Detected ISO type: {iso_type}")
        
        if iso_type == "windows":
            return create_windows(iso_path, device, writer)
        else:
            return create_linux(iso_path, device, writer)
    
    elif command == "create-win":
        if len(sys.argv) < 3:
            print("[ERROR] Need ISO file")
            sys.exit(1)
        iso_path = sys.argv[2]
        device = sys.argv[3] if len(sys.argv) > 3 else None
        return create_windows(iso_path, device, writer)
    
    elif command == "create-linux":
        if len(sys.argv) < 3:
            print("[ERROR] Need ISO file")
            sys.exit(1)
        iso_path = sys.argv[2]
        device = sys.argv[3] if len(sys.argv) > 3 else None
        return create_linux(iso_path, device, writer)
    
    else:
        print(f"[ERROR] Unknown command: {command}")
        sys.exit(1)

def create_windows(iso_path: str, device: str, writer: USBWriter) -> bool:
    """Create Windows USB (using Ventoy)"""
    if not device:
        device = select_device()
        if not device:
            return False
    
    print(f"[ACTION] Creating Windows USB on {device}")
    print(f"[WARNING] ALL DATA ON {device} WILL BE DESTROYED!")
    
    confirm = input(f"Type 'YES' to continue: ")
    if confirm != "YES":
        print("[CANCELLED]")
        return False
    
    return writer.write_with_ventoy(iso_path, device)

def create_linux(iso_path: str, device: str, writer: USBWriter) -> bool:
    """Create Linux USB (using dd)"""
    if not device:
        device = select_device()
        if not device:
            return False
    
    print(f"[ACTION] Creating Linux USB on {device}")
    print(f"[WARNING] ALL DATA ON {device} WILL BE DESTROYED!")
    
    confirm = input(f"Type 'YES' to continue: ")
    if confirm != "YES":
        print("[CANCELLED]")
        return False
    
    return writer.write_linux_iso(iso_path, device)

def select_device() -> str:
    """Let user select USB device"""
    devices = get_usb_devices()
    
    if not devices:
        print("[ERROR] No USB devices found")
        return ""
    
    if len(devices) == 1:
        return devices[0].path
    
    print("Select USB device:")
    for i, dev in enumerate(devices, 1):
        print(f"  {i}. {dev}")
    
    try:
        choice = int(input("Enter number: "))
        if 1 <= choice <= len(devices):
            return devices[choice-1].path
    except:
        pass
    
    print("[ERROR] Invalid selection")
    return ""

# ========== EXECUTE ==========
if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("[INFO] Needs root for USB access. Running with sudo...")
        os.execvp("sudo", ["sudo", "python3"] + sys.argv)
    
    success = main()
    sys.exit(0 if success else 1)