#!/usr/bin/env python3
"""
Production-grade USB Bootable Creator
Safe, fast, and feature-rich
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
import hashlib
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import time

# ========== DATA STRUCTURES ==========
class ISOType(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"
    MACOS = "macos"

@dataclass
class USBDevice:
    path: str
    model: str
    size_bytes: int
    removable: bool
    vendor: str = ""
    serial: str = ""
    partitions: List[str] = None
    
    def __post_init__(self):
        if self.partitions is None:
            self.partitions = []
    
    @property
    def size_gb(self) -> float:
        return self.size_bytes / (1024**3)
    
    @property
    def size_human(self) -> str:
        """Human readable size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if self.size_bytes < 1024.0:
                return f"{self.size_bytes:.1f} {unit}"
            self.size_bytes /= 1024.0
        return f"{self.size_bytes:.2f} PB"

@dataclass
class ISOInfo:
    path: Path
    size: int
    type: ISOType
    checksum: str = ""
    label: str = ""
    hybrid_boot: bool = False
    uefi_support: bool = False
    
    @property
    def size_human(self) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if self.size < 1024.0:
                return f"{self.size:.1f} {unit}"
            self.size /= 1024.0
        return f"{self.size:.2f} TB"

class SafetyCheckError(Exception):
    """Raised when safety check fails"""
    pass

# ========== CONFIGURATION ==========
class Config:
    DEFAULT_BLOCK_SIZE = "4M"
    DD_FLAGS = ["bs=4M", "status=progress", "conv=fsync"]
    VENTOY_URL = "https://github.com/ventoy/Ventoy/releases/latest/download/ventoy-1.0.97-linux.tar.gz"
    
    # ISO detection patterns
    WINDOWS_SIGNATURES = [
        "/sources/install.wim",
        "/sources/install.esd",
        "/bootmgr",
        "/boot/boot.sdi",
        "/efi/microsoft"
    ]
    
    LINUX_SIGNATURES = [
        "/isolinux/isolinux.bin",
        "/boot/grub/grub.cfg",
        "/casper/filesystem.squashfs",
        "/live/filesystem.squashfs",
        "/arch/boot/x86_64"
    ]

# ========== CORE UTILITIES (SAFE VERSION) ==========
class SafeCommand:
    """Safe command execution without shell=True"""
    
    @staticmethod
    def run(cmd: List[str], sudo: bool = False, 
            capture: bool = False, check: bool = True) -> Tuple[bool, str, str]:
        """
        Run command safely
        Returns: (success, stdout, stderr)
        """
        try:
            if sudo and os.geteuid() != 0:
                cmd = ["sudo"] + cmd
            
            if capture:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=check
                )
                return (
                    result.returncode == 0,
                    result.stdout,
                    result.stderr
                )
            else:
                result = subprocess.run(cmd, check=check)
                return (result.returncode == 0, "", "")
                
        except subprocess.CalledProcessError as e:
            return (False, e.stdout if hasattr(e, 'stdout') else "", 
                    e.stderr if hasattr(e, 'stderr') else str(e))
        except Exception as e:
            return (False, "", str(e))
    
    @staticmethod
    def run_shell(cmd: str, **kwargs):
        """Only use when absolutely necessary, with sanitized input"""
        # Escape single quotes for shell safety
        cmd = cmd.replace("'", "'\"'\"'")
        return SafeCommand.run(["sh", "-c", cmd], **kwargs)

class HashUtil:
    """File hashing utilities"""
    
    @staticmethod
    def calculate(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
        """Calculate file hash"""
        hash_func = hashlib.new(algorithm)
        chunk_size = 8192
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    @staticmethod
    def verify(source: Union[str, Path], target: Union[str, Path]) -> bool:
        """Verify two files have same content"""
        if not os.path.exists(source) or not os.path.exists(target):
            return False
        
        # Quick size check first
        if os.path.getsize(source) != os.path.getsize(target):
            return False
        
        # Compare first 1MB for quick check
        with open(source, 'rb') as f1, open(target, 'rb') as f2:
            if f1.read(1024*1024) != f2.read(1024*1024):
                return False
        
        # Full hash if needed
        return HashUtil.calculate(source) == HashUtil.calculate(target)

# ========== DEVICE MANAGEMENT ==========
class DeviceManager:
    """Safe device detection and management"""
    
    @staticmethod
    def get_usb_devices() -> List[USBDevice]:
        """Get all USB devices using lsblk -b (bytes output)"""
        devices = []
        
        # Use lsblk with bytes output (-b)
        success, stdout, stderr = SafeCommand.run([
            "lsblk", "-b", "-J", "-o",
            "NAME,PATH,MODEL,VENDOR,SIZE,TYPE,RM,SERIAL,MOUNTPOINT"
        ], capture=True)
        
        if not success:
            # Fallback to sysfs
            return DeviceManager._fallback_detection()
        
        try:
            data = json.loads(stdout)
            
            for device in data.get("blockdevices", []):
                if device.get("type") == "disk" and device.get("rm") == 1:
                    # Check if any partition is mounted as system
                    if DeviceManager._is_system_disk(device):
                        continue
                    
                    # Get partitions
                    partitions = []
                    for child in device.get("children", []):
                        partitions.append(child.get("name", ""))
                    
                    # Parse size (already in bytes from -b flag)
                    size = int(device.get("size", 0))
                    
                    devices.append(USBDevice(
                        path=device.get("path", ""),
                        model=device.get("model", "Unknown").strip(),
                        size_bytes=size,
                        removable=True,
                        vendor=device.get("vendor", "").strip(),
                        serial=device.get("serial", "").strip(),
                        partitions=partitions
                    ))
                    
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[WARN] Failed to parse lsblk: {e}")
            return DeviceManager._fallback_detection()
        
        return devices
    
    @staticmethod
    def _is_system_disk(device_data: Dict) -> bool:
        """Check if disk has system partitions"""
        system_mounts = {"/", "/boot", "/boot/efi", "/home", "/var"}
        
        for child in device_data.get("children", []):
            mountpoint = child.get("mountpoint")
            if mountpoint in system_mounts:
                return True
        
        return False
    
    @staticmethod
    def _fallback_detection() -> List[USBDevice]:
        """Fallback detection using sysfs"""
        devices = []
        
        sys_block = Path("/sys/block")
        if not sys_block.exists():
            return devices
        
        for dev_path in sys_block.iterdir():
            dev_name = dev_path.name
            
            # Skip non-USB devices
            if dev_name.startswith(("loop", "ram", "sr", "dm-")):
                continue
            
            # Check if removable
            removable_file = dev_path / "removable"
            if not removable_file.exists():
                continue
            
            if removable_file.read_text().strip() != "1":
                continue
            
            # Get size
            size_file = dev_path / "size"
            if not size_file.exists():
                continue
            
            sectors = int(size_file.read_text().strip())
            size_bytes = sectors * 512
            
            # Get model
            model = "Unknown"
            model_file = dev_path / "device" / "model"
            if model_file.exists():
                model = model_file.read_text().strip()
            
            # Get vendor
            vendor = ""
            vendor_file = dev_path / "device" / "vendor"
            if vendor_file.exists():
                vendor = vendor_file.read_text().strip()
            
            devices.append(USBDevice(
                path=f"/dev/{dev_name}",
                model=model,
                size_bytes=size_bytes,
                removable=True,
                vendor=vendor
            ))
        
        return devices
    
    @staticmethod
    def unmount_device(device_path: str) -> bool:
        """Unmount all partitions on a device"""
        # First, try to unmount by device path
        success, stdout, stderr = SafeCommand.run(
            ["umount", f"{device_path}*"],
            sudo=True,
            capture=True,
            check=False  # Don't fail if nothing mounted
        )
        
        # Also check mounted partitions via /proc/mounts
        try:
            with open("/proc/mounts", "r") as f:
                mounts = f.readlines()
            
            for mount in mounts:
                if device_path in mount:
                    mount_point = mount.split()[1]
                    SafeCommand.run(["umount", mount_point], sudo=True, check=False)
        except:
            pass
        
        return True
    
    @staticmethod
    def get_device_info(device_path: str) -> Optional[Dict]:
        """Get detailed info about a specific device"""
        success, stdout, stderr = SafeCommand.run([
            "lsblk", "-b", "-J", device_path
        ], capture=True)
        
        if not success:
            return None
        
        try:
            data = json.loads(stdout)
            if data.get("blockdevices"):
                return data["blockdevices"][0]
        except:
            pass
        
        return None

# ========== ISO ANALYSIS ==========
class ISOAnalyzer:
    """Smart ISO analysis without using shell=True"""
    
    @staticmethod
    def analyze(iso_path: Union[str, Path]) -> ISOInfo:
        """Analyze ISO file and return detailed info"""
        iso_path = Path(iso_path)
        
        if not iso_path.exists():
            raise FileNotFoundError(f"ISO not found: {iso_path}")
        
        # Basic info
        size = iso_path.stat().st_size
        checksum = HashUtil.calculate(iso_path, "md5")
        
        # Detect type
        iso_type, label = ISOAnalyzer._detect_type(iso_path)
        
        # Check hybrid boot
        hybrid = ISOAnalyzer._check_hybrid(iso_path)
        
        # Check UEFI support
        uefi = ISOAnalyzer._check_uefi(iso_path)
        
        return ISOInfo(
            path=iso_path,
            size=size,
            type=iso_type,
            checksum=checksum,
            label=label,
            hybrid_boot=hybrid,
            uefi_support=uefi
        )
    
    @staticmethod
    def _detect_type(iso_path: Path) -> Tuple[ISOType, str]:
        """Detect ISO type by examining contents"""
        
        # Try to mount ISO temporarily
        with tempfile.TemporaryDirectory() as mount_point:
            # Mount ISO
            success, stdout, stderr = SafeCommand.run([
                "mount", "-o", "ro,loop", str(iso_path), mount_point
            ], sudo=True, capture=True)
            
            if not success:
                # Fallback: check file signatures without mounting
                return ISOAnalyzer._detect_fallback(iso_path)
            
            try:
                # Check for Windows signatures
                for sig in Config.WINDOWS_SIGNATURES:
                    if (Path(mount_point) / sig.lstrip('/')).exists():
                        # Get Windows version if possible
                        label = ISOAnalyzer._get_windows_label(Path(mount_point))
                        return ISOType.WINDOWS, label
                
                # Check for Linux signatures
                for sig in Config.LINUX_SIGNATURES:
                    if (Path(mount_point) / sig.lstrip('/')).exists():
                        label = ISOAnalyzer._get_linux_label(Path(mount_point))
                        return ISOType.LINUX, label
                
                # Check for macOS
                if (Path(mount_point) / "System" / "Library" / "CoreServices" / "boot.efi").exists():
                    return ISOType.MACOS, "macOS Installer"
                
                # Check for hybrid ISO (has isolinux.bin at offset 32768)
                with open(iso_path, 'rb') as f:
                    f.seek(32768)
                    if f.read(4) == b'ISOL':
                        return ISOType.HYBRID, "Hybrid ISO"
                
            finally:
                # Always unmount
                SafeCommand.run(["umount", mount_point], sudo=True, check=False)
        
        return ISOType.UNKNOWN, "Unknown"
    
    @staticmethod
    def _detect_fallback(iso_path: Path) -> Tuple[ISOType, str]:
        """Fallback detection using file command"""
        success, stdout, stderr = SafeCommand.run(
            ["file", "-b", str(iso_path)], capture=True
        )
        
        if success:
            file_info = stdout.lower()
            if "windows" in file_info or "microsoft" in file_info:
                return ISOType.WINDOWS, "Windows Installer"
            elif "linux" in file_info:
                return ISOType.LINUX, "Linux Distro"
            elif "mac" in file_info:
                return ISOType.MACOS, "macOS"
            elif "iso 9660" in file_info:
                return ISOType.HYBRID, "Bootable ISO"
        
        return ISOType.UNKNOWN, "Unknown"
    
    @staticmethod
    def _check_hybrid(iso_path: Path) -> bool:
        """Check if ISO is hybrid (bootable from USB with dd)"""
        try:
            with open(iso_path, 'rb') as f:
                # Check for MBR boot signature at offset 510
                f.seek(510)
                if f.read(2) == b'\x55\xAA':
                    return True
                
                # Check for isolinux at sector 64 (32768 bytes)
                f.seek(32768)
                if f.read(4) == b'ISOL':
                    return True
        except:
            pass
        
        return False
    
    @staticmethod
    def _check_uefi(iso_path: Path) -> bool:
        """Check if ISO supports UEFI boot"""
        # Look for EFI directory in ISO
        success, stdout, stderr = SafeCommand.run_shell(
            f"isoinfo -R -f -i '{iso_path}' | grep -i 'efi' | head -1",
            capture=True
        )
        return success and stdout.strip() != ""
    
    @staticmethod
    def _get_windows_label(mount_point: Path) -> str:
        """Extract Windows version label"""
        try:
            # Check for ei.cfg or version.txt
            version_files = [
                mount_point / "sources" / "ei.cfg",
                mount_point / "sources" / "idwbinfo.txt",
                mount_point / "setup.exe"
            ]
            
            for vfile in version_files:
                if vfile.exists():
                    success, stdout, stderr = SafeCommand.run(
                        ["strings", str(vfile)], capture=True
                    )
                    if success:
                        for line in stdout.split('\n'):
                            if "Windows" in line and "Version" in line:
                                return line.strip()
        except:
            pass
        
        return "Windows Installer"
    
    @staticmethod
    def _get_linux_label(mount_point: Path) -> str:
        """Extract Linux distribution name"""
        try:
            # Check for .disk/info
            disk_info = mount_point / ".disk" / "info"
            if disk_info.exists():
                return disk_info.read_text().split(' ')[0]
            
            # Check for lsb-release
            lsb_release = mount_point / "etc" / "lsb-release"
            if lsb_release.exists():
                content = lsb_release.read_text()
                for line in content.split('\n'):
                    if line.startswith("DISTRIB_DESCRIPTION="):
                        return line.split('=')[1].strip('"')
        except:
            pass
        
        return "Linux Distribution"

# ========== WRITERS ==========
class BaseWriter:
    """Base class for all writers"""
    
    def __init__(self):
        self.check_dependencies()
    
    def check_dependencies(self) -> List[str]:
        """Check and return missing dependencies"""
        missing = []
        for dep in self.REQUIRED_DEPS:
            if not shutil.which(dep):
                missing.append(dep)
        return missing
    
    def write(self, iso_info: ISOInfo, device: USBDevice, 
              verify: bool = True, dry_run: bool = False) -> Tuple[bool, str]:
        """Write ISO to device"""
        raise NotImplementedError
    
    def verify_write(self, iso_info: ISOInfo, device: USBDevice) -> bool:
        """Verify the write was successful"""
        raise NotImplementedError

class DdWriter(BaseWriter):
    """Writer for hybrid ISOs (most Linux distros)"""
    
    REQUIRED_DEPS = ["dd", "sync"]
    
    def write(self, iso_info: ISOInfo, device: USBDevice,
              verify: bool = True, dry_run: bool = False) -> Tuple[bool, str]:
        
        print(f"[INFO] Writing with dd: {iso_info.path.name} → {device.path}")
        
        if dry_run:
            print(f"[DRY-RUN] Would run: dd if={iso_info.path} of={device.path} "
                  f"bs={Config.DEFAULT_BLOCK_SIZE} status=progress conv=fsync")
            return True, "Dry run completed"
        
        # Unmount device first
        DeviceManager.unmount_device(device.path)
        
        # Build dd command
        dd_cmd = [
            "dd",
            f"if={iso_info.path}",
            f"of={device.path}",
            "bs=4M",
            "status=progress",
            "conv=fsync"
        ]
        
        print(f"[EXEC] {' '.join(dd_cmd)}")
        
        # Execute dd
        success, stdout, stderr = SafeCommand.run(dd_cmd, sudo=True, capture=True)
        
        if not success:
            return False, f"dd failed: {stderr}"
        
        # Sync
        SafeCommand.run(["sync"], sudo=True)
        
        # Verify if requested
        if verify:
            if not self.verify_write(iso_info, device):
                return False, "Verification failed"
        
        return True, "Write completed successfully"
    
    def verify_write(self, iso_info: ISOInfo, device: USBDevice) -> bool:
        """Verify write by comparing checksums of first 100MB"""
        print("[INFO] Verifying write...")
        
        # Create temp file for verification
        with tempfile.NamedTemporaryFile() as tmp:
            # Read first 100MB from device
            verify_size = min(100 * 1024 * 1024, iso_info.size)
            
            dd_cmd = [
                "dd",
                f"if={device.path}",
                f"of={tmp.name}",
                f"bs={verify_size}",
                "count=1"
            ]
            
            success, stdout, stderr = SafeCommand.run(dd_cmd, sudo=True, capture=True)
            
            if not success:
                print(f"[WARN] Could not read from device: {stderr}")
                return True  # Skip verification if failed
            
            # Read same amount from ISO
            with open(iso_info.path, 'rb') as iso_file:
                iso_data = iso_file.read(verify_size)
            
            # Calculate hashes
            tmp_hash = HashUtil.calculate(tmp.name)
            
            # Calculate hash of ISO data
            iso_hash = hashlib.sha256(iso_data).hexdigest()
            
            if tmp_hash == iso_hash:
                print("[INFO] Verification passed")
                return True
            else:
                print(f"[ERROR] Verification failed: {tmp_hash[:16]} != {iso_hash[:16]}")
                return False

class VentoyWriter(BaseWriter):
    """Writer using Ventoy (handles Windows, non-hybrid Linux, etc.)"""
    
    REQUIRED_DEPS = ["ventoy", "mount", "umount", "tar"]
    
    def __init__(self):
        super().__init__()
        self.ventoy_path = self._find_ventoy()
    
    def _find_ventoy(self) -> str:
        """Find Ventoy executable"""
        # Check common locations
        locations = [
            "ventoy",
            "/usr/local/bin/ventoy",
            "/usr/bin/ventoy",
            "/opt/ventoy/ventoy"
        ]
        
        for loc in locations:
            if shutil.which(loc):
                return loc
        
        # Try to find in PATH
        ventoy_path = shutil.which("Ventoy2Disk.sh") or shutil.which("VentoyGUI.sh")
        if ventoy_path:
            return ventoy_path
        
        # Not found, will attempt to download
        return ""
    
    def _download_ventoy(self) -> str:
        """Download Ventoy if not installed"""
        print("[INFO] Ventoy not found, downloading...")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Download
            success, stdout, stderr = SafeCommand.run([
                "wget", "-q", Config.VENTOY_URL, "-O", f"{tmpdir}/ventoy.tar.gz"
            ], capture=True)
            
            if not success:
                return ""
            
            # Extract
            SafeCommand.run([
                "tar", "-xzf", f"{tmpdir}/ventoy.tar.gz", "-C", tmpdir
            ])
            
            # Find ventoy binary
            for root, dirs, files in os.walk(tmpdir):
                if "ventoy" in files:
                    ventoy_path = os.path.join(root, "ventoy")
                    os.chmod(ventoy_path, 0o755)
                    
                    # Copy to /tmp for this session
                    temp_ventoy = "/tmp/ventoy_latest"
                    shutil.copy2(ventoy_path, temp_ventoy)
                    os.chmod(temp_ventoy, 0o755)
                    
                    return temp_ventoy
        
        return ""
    
    def write(self, iso_info: ISOInfo, device: USBDevice,
              verify: bool = True, dry_run: bool = False) -> Tuple[bool, str]:
        
        print(f"[INFO] Writing with Ventoy: {iso_info.path.name} → {device.path}")
        
        # Ensure Ventoy is available
        if not self.ventoy_path:
            self.ventoy_path = self._download_ventoy()
            if not self.ventoy_path:
                return False, "Ventoy not found and could not download"
        
        if dry_run:
            print(f"[DRY-RUN] Would install Ventoy to {device.path}")
            print(f"[DRY-RUN] Would copy {iso_info.path} to Ventoy partition")
            return True, "Dry run completed"
        
        # Unmount device
        DeviceManager.unmount_device(device.path)
        
        # Install Ventoy
        print(f"[INFO] Installing Ventoy to {device.path}")
        success, stdout, stderr = SafeCommand.run(
            [self.ventoy_path, "-i", "-I", device.path],
            sudo=True,
            capture=True
        )
        
        if not success:
            return False, f"Ventoy installation failed: {stderr}"
        
        # Wait for device to settle
        time.sleep(2)
        
        # Find Ventoy partition
        ventoy_part = self._find_ventoy_partition(device.path)
        if not ventoy_part:
            return False, "Could not find Ventoy partition"
        
        # Mount and copy ISO
        with tempfile.TemporaryDirectory() as mount_point:
            # Mount partition
            success, stdout, stderr = SafeCommand.run(
                ["mount", ventoy_part, mount_point],
                sudo=True,
                capture=True
            )
            
            if not success:
                return False, f"Failed to mount {ventoy_part}: {stderr}"
            
            try:
                # Copy ISO
                dest = Path(mount_point) / iso_info.path.name
                print(f"[INFO] Copying ISO to {dest}")
                shutil.copy2(iso_info.path, dest)
                
                # Sync
                SafeCommand.run(["sync"], sudo=True)
                
            finally:
                # Unmount
                SafeCommand.run(["umount", mount_point], sudo=True, check=False)
        
        return True, "Ventoy setup completed successfully"
    
    def _find_ventoy_partition(self, device_path: str) -> str:
        """Find the Ventoy data partition"""
        # Try common partition names
        candidates = [
            f"{device_path}1",
            f"{device_path}p1",
            f"{device_path}2",
            f"{device_path}p2"
        ]
        
        for candidate in candidates:
            if os.path.exists(candidate):
                # Check if it's Ventoy partition by looking for ventoy directory
                with tempfile.TemporaryDirectory() as tmp:
                    success, stdout, stderr = SafeCommand.run(
                        ["mount", candidate, tmp],
                        sudo=True,
                        capture=True,
                        check=False
                    )
                    
                    if success:
                        if (Path(tmp) / "ventoy").exists() or \
                           (Path(tmp) / "ventoy").is_dir():
                            SafeCommand.run(["umount", tmp], sudo=True, check=False)
                            return candidate
                        SafeCommand.run(["umount", tmp], sudo=True, check=False)
        
        return ""

# ========== SAFETY CHECKS ==========
class SafetySystem:
    """Comprehensive safety checking"""
    
    @staticmethod
    def check_all(iso_info: ISOInfo, device: USBDevice, 
                  force: bool = False) -> Tuple[bool, List[str]]:
        """Run all safety checks"""
        warnings = []
        errors = []
        
        # 1. Check ISO exists
        if not iso_info.path.exists():
            errors.append(f"ISO not found: {iso_info.path}")
        
        # 2. Check device exists
        if not os.path.exists(device.path):
            errors.append(f"Device not found: {device.path}")
        
        # 3. Check if device is USB
        if not device.removable and not force:
            errors.append(f"Device {device.path} is not removable (likely internal disk!)")
        
        # 4. Check size
        if iso_info.size > device.size_bytes * 0.95:  # 95% of device size
            warnings.append(f"ISO ({iso_info.size_human}) is very large for device "
                          f"({device.size_human})")
        
        # 5. Check if device is mounted
        if SafetySystem._is_mounted(device.path) and not force:
            errors.append(f"Device {device.path} has mounted partitions")
        
        # 6. Check if system disk
        if SafetySystem._is_system_disk(device.path) and not force:
            errors.append(f"Device {device.path} appears to be a system disk!")
        
        if errors:
            return False, errors + warnings
        elif warnings:
            return True, warnings
        else:
            return True, []
    
    @staticmethod
    def _is_mounted(device_path: str) -> bool:
        """Check if device has mounted partitions"""
        try:
            with open("/proc/mounts", "r") as f:
                mounts = f.read()
                return device_path in mounts
        except:
            return False
    
    @staticmethod
    def _is_system_disk(device_path: str) -> bool:
        """Check if device is a system disk"""
        system_disks = []
        
        # Get root filesystem device
        success, stdout, stderr = SafeCommand.run(
            ["findmnt", "-n", "-o", "SOURCE", "/"], capture=True
        )
        
        if success:
            root_dev = stdout.strip()
            # Extract disk name (e.g., /dev/sda2 -> sda)
            import re
            match = re.match(r"/dev/([a-z]+)\d*", root_dev)
            if match:
                system_disks.append(f"/dev/{match.group(1)}")
        
        return device_path in system_disks

# ========== MAIN APPLICATION ==========
class USBCreatorApp:
    """Main application class"""
    
    def __init__(self):
        self.writers = {
            "dd": DdWriter(),
            "ventoy": VentoyWriter()
        }
    
    def list_devices(self, json_output: bool = False) -> None:
        """List available USB devices"""
        devices = DeviceManager.get_usb_devices()
        
        if json_output:
            data = [
                {
                    "path": d.path,
                    "model": d.model,
                    "size_bytes": d.size_bytes,
                    "size_human": d.size_human,
                    "removable": d.removable,
                    "vendor": d.vendor
                }
                for d in devices
            ]
            print(json.dumps(data, indent=2))
        else:
            if not devices:
                print("No USB devices found")
                return
            
            print(f"\n{'='*60}")
            print("Available USB Devices:")
            print(f"{'='*60}")
            
            for i, device in enumerate(devices, 1):
                print(f"\n{i}. {device.path}")
                print(f"   Model:  {device.model}")
                print(f"   Size:   {device.size_human}")
                print(f"   Vendor: {device.vendor}")
                if device.partitions:
                    print(f"   Partitions: {', '.join(device.partitions[:3])}")
                    if len(device.partitions) > 3:
                        print(f"               ... and {len(device.partitions)-3} more")
    
    def analyze_iso(self, iso_path: str, json_output: bool = False) -> None:
        """Analyze ISO file"""
        try:
            iso_info = ISOAnalyzer.analyze(iso_path)
            
            if json_output:
                data = {
                    "path": str(iso_info.path),
                    "size": iso_info.size,
                    "size_human": iso_info.size_human,
                    "type": iso_info.type.value,
                    "checksum": iso_info.checksum,
                    "label": iso_info.label,
                    "hybrid_boot": iso_info.hybrid_boot,
                    "uefi_support": iso_info.uefi_support
                }
                print(json.dumps(data, indent=2))
            else:
                print(f"\n{'='*60}")
                print(f"ISO Analysis: {iso_info.path.name}")
                print(f"{'='*60}")
                print(f"Type:        {iso_info.type.value.upper()} ({iso_info.label})")
                print(f"Size:        {iso_info.size_human}")
                print(f"Checksum:    {iso_info.checksum}")
                print(f"Hybrid Boot: {'Yes' if iso_info.hybrid_boot else 'No'}")
                print(f"UEFI Support: {'Yes' if iso_info.uefi_support else 'No'}")
                
                # Writer recommendation
                if iso_info.type == ISOType.WINDOWS:
                    print(f"Recommended: Ventoy writer")
                elif iso_info.hybrid_boot:
                    print(f"Recommended: dd writer (fast)")
                else:
                    print(f"Recommended: Ventoy writer")
        
        except Exception as e:
            print(f"[ERROR] Failed to analyze ISO: {e}")
    
    def create(self, iso_path: str, device_path: Optional[str] = None,
               writer: Optional[str] = None, verify: bool = True,
               dry_run: bool = False, force: bool = False,
               checksum: bool = False) -> bool:
        """Create bootable USB"""
        
        # Check root
        if os.geteuid() != 0:
            print("[ERROR] This operation requires root privileges")
            print("Please run with: sudo usb_creator.py create ...")
            return False
        
        # Analyze ISO
        print("[INFO] Analyzing ISO...")
        try:
            iso_info = ISOAnalyzer.analyze(iso_path)
        except Exception as e:
            print(f"[ERROR] Failed to analyze ISO: {e}")
            return False
        
        print(f"[INFO] Detected: {iso_info.label} ({iso_info.type.value})")
        
        # Select device
        if not device_path:
            devices = DeviceManager.get_usb_devices()
            if not devices:
                print("[ERROR] No USB devices found")
                return False
            
            if len(devices) == 1:
                device = devices[0]
                print(f"[INFO] Auto-selected: {device.path}")
            else:
                print("\nAvailable USB devices:")
                for i, dev in enumerate(devices, 1):
                    print(f"{i}. {dev.path} ({dev.size_human}) - {dev.model}")
                
                try:
                    choice = int(input(f"\nSelect device (1-{len(devices)}): "))
                    if 1 <= choice <= len(devices):
                        device = devices[choice-1]
                    else:
                        print("[ERROR] Invalid selection")
                        return False
                except ValueError:
                    print("[ERROR] Invalid input")
                    return False
        else:
            # Find device by path
            devices = DeviceManager.get_usb_devices()
            device = None
            for dev in devices:
                if dev.path == device_path:
                    device = dev
                    break
            
            if not device:
                print(f"[ERROR] Device not found or not USB: {device_path}")
                return False
        
        # Safety checks
        print("[INFO] Running safety checks...")
        safe, messages = SafetySystem.check_all(iso_info, device, force)
        
        if messages:
            print("\n[SAFETY CHECKS]:")
            for msg in messages:
                if "ERROR" in msg.upper() or "!" in msg:
                    print(f"  ⚠️  {msg}")
                else:
                    print(f"  ℹ️  {msg}")
        
        if not safe and not force:
            print("\n[ERROR] Safety checks failed. Use --force to override.")
            return False
        
        # Select writer
        if not writer:
            if iso_info.type == ISOType.WINDOWS:
                writer = "ventoy"
            elif iso_info.hybrid_boot:
                writer = "dd"
            else:
                writer = "ventoy"
        
        if writer not in self.writers:
            print(f"[ERROR] Unknown writer: {writer}")
            return False
        
        # Check dependencies
        missing_deps = self.writers[writer].check_dependencies()
        if missing_deps:
            print(f"[ERROR] Missing dependencies for {writer}: {', '.join(missing_deps)}")
            
            if writer == "ventoy":
                print("\nTo install Ventoy:")
                print(f"  wget {Config.VENTOY_URL}")
                print("  tar -xzf ventoy-*.tar.gz")
                print("  sudo cp ventoy*/ventoy /usr/local/bin/")
            
            return False
        
        # Confirm (unless forced or dry run)
        if not force and not dry_run:
            print(f"\n{'='*60}")
            print("CONFIRMATION REQUIRED")
            print(f"{'='*60}")
            print(f"ISO:      {iso_info.path.name}")
            print(f"Device:   {device.path} ({device.model})")
            print(f"Writer:   {writer}")
            print(f"\n⚠️  ALL DATA ON {device.path} WILL BE DESTROYED!")
            
            response = input(f"\nType 'YES' to continue: ")
            if response != "YES":
                print("[CANCELLED]")
                return False
        
        # Calculate checksum if requested
        if checksum:
            print("[INFO] Calculating ISO checksum...")
            checksum_value = HashUtil.calculate(iso_info.path)
            print(f"[INFO] SHA256: {checksum_value}")
        
        # Execute write
        print(f"\n[INFO] Starting write operation...")
        success, message = self.writers[writer].write(
            iso_info, device, verify=verify, dry_run=dry_run
        )
        
        if success:
            print(f"\n✅ SUCCESS: {message}")
            
            # Post-write instructions
            print(f"\n{'='*60}")
            print("NEXT STEPS:")
            print(f"{'='*60}")
            
            if writer == "ventoy":
                print("1. USB is ready with Ventoy")
                print("2. You can add more ISOs by copying them to the USB")
                print("3. Boot from USB and select your ISO from Ventoy menu")
            else:
                print("1. USB is ready to boot")
                print("2. Boot from USB (usually F12, F10, or Esc during startup)")
            
            print(f"\nYou can safely eject: sudo eject {device.path}")
            
            return True
        else:
            print(f"\n❌ FAILED: {message}")
            return False

# ========== CLI INTERFACE ==========
def main():
    parser = argparse.ArgumentParser(
        description="Production-grade USB Bootable Creator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                        # List USB devices
  %(prog)s analyze ubuntu.iso          # Analyze ISO file
  %(prog)s create windows10.iso        # Auto-detect and create
  %(prog)s create --dry-run arch.iso   # Show what would be done
  %(prog)s create --verify fedora.iso  # Create with verification
  %(prog)s create --json ubuntu.iso    # JSON output for scripting
        
Advanced:
  %(prog)s create --writer=dd --force ubuntu.iso /dev/sdb
  %(prog)s create --checksum --no-verify windows11.iso
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List USB devices")
    list_parser.add_argument("--json", action="store_true", help="JSON output")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze ISO file")
    analyze_parser.add_argument("iso_path", help="Path to ISO file")
    analyze_parser.add_argument("--json", action="store_true", help="JSON output")
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create bootable USB")
    create_parser.add_argument("iso_path", help="Path to ISO file")
    create_parser.add_argument("device_path", nargs="?", help="USB device path (e.g., /dev/sdb)")
    create_parser.add_argument("--writer", choices=["dd", "ventoy"], 
                              help="Force specific writer")
    create_parser.add_argument("--verify", action="store_true", default=True,
                              help="Verify write after completion")
    create_parser.add_argument("--no-verify", action="store_false", dest="verify",
                              help="Skip verification")
    create_parser.add_argument("--dry-run", action="store_true",
                              help="Show what would be done without executing")
    create_parser.add_argument("--force", action="store_true",
                              help="Skip safety checks (DANGEROUS)")
    create_parser.add_argument("--checksum", action="store_true",
                              help="Calculate and display ISO checksum")
    create_parser.add_argument("--json", action="store_true",
                              help="JSON output for automation")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    app = USBCreatorApp()
    
    try:
        if args.command == "list":
            app.list_devices(json_output=args.json)
            return 0
        
        elif args.command == "analyze":
            if not os.path.exists(args.iso_path):
                print(f"[ERROR] ISO not found: {args.iso_path}")
                return 1
            app.analyze_iso(args.iso_path, json_output=args.json)
            return 0
        
        elif args.command == "create":
            success = app.create(
                iso_path=args.iso_path,
                device_path=args.device_path,
                writer=args.writer,
                verify=args.verify,
                dry_run=args.dry_run,
                force=args.force,
                checksum=args.checksum
            )
            return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    # Check if we have required privileges
    if len(sys.argv) > 1 and sys.argv[1] == "create" and os.geteuid() != 0:
        print("[ERROR] 'create' command requires root privileges")
        print("Please run with: sudo python3 usb_creator.py create ...")
        sys.exit(1)
    
    sys.exit(main())