#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZIPHero: A multipurpose tool for extracting and repairing ZIP, 7z, RAR, and TAR archives.
Includes:
- Automatic backup before repair
- Multiple repair strategies for ZIP
- 7z, RAR, and TAR extraction
- Basic "decompress-recompress" repair approach for 7z and RAR
- GUI with Tkinter for easy usage
- Command-line support for advanced usage
"""

import zipfile
import os
import shutil
import logging
import hashlib
import sys
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import tempfile
from pathlib import Path
from datetime import datetime
import json
import zlib
import struct
import tkinter as tk
from tkinter import filedialog, ttk
import webbrowser

# Attempt to import rarfile gracefully
try:
    import rarfile
except ImportError:
    rarfile = None
    print("WARNING: 'rarfile' not installed. RAR extraction/repair will be unavailable.")

# Attempt to import py7zr gracefully
try:
    import py7zr
except ImportError:
    py7zr = None
    print("WARNING: 'py7zr' not installed. 7z extraction/repair will be unavailable.")

# Attempt to import patoolib gracefully
try:
    import patoolib
except ImportError:
    patoolib = None
    print("WARNING: 'patoolib' not installed. TAR extraction (and other patool features) may be unavailable.")

# Attempt to import pyzipper for enhanced ZIP handling
try:
    import pyzipper
except ImportError:
    pyzipper = None
    print("WARNING: 'pyzipper' not installed. Password-protected ZIP handling will be unavailable.")

# Platform-specific imports (used for Windows-only UI enhancements)
if sys.platform.startswith('win'):
    import ctypes
    from ctypes import wintypes


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('zip_processor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Exceptions
class ZipProcessingError(Exception):
    error_message = "An error occurred during ZIP processing"

    def __init__(self, message: str = None):
        self.message = message or self.error_message

    def __str__(self):
        return self.message


class ZipRepairError(Exception):
    error_message = "An error occurred during ZIP repair"

    def __init__(self, message: str = None):
        self.message = message or self.error_message

    def __str__(self):
        return self.message


class ZipUnlockError(Exception):
    error_message = "An error occurred during ZIP unlocking"

    def __init__(self, message: str = None):
        self.message = message or self.error_message

    def __str__(self):
        return self.message


@contextmanager
def error_handler(operation: str, skip_on_error: bool = True):
    """Context manager for handling operations with optional skip on error"""
    try:
        yield
    except Exception:
        logging.exception(f"Error during {operation}")
        if not skip_on_error:
            raise


def verify_file_integrity(file_path: str) -> bool:
    """Verify file integrity using a basic MD5 checksum read."""
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5()
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                file_hash.update(chunk)
        # Optionally, we could do something with file_hash.hexdigest() here.
        return True
    except Exception:
        logging.exception(f"File integrity check failed for {file_path}")
        return False


class ArchiveFormat:
    """Archive format detection and validation"""
    SIGNATURES = {
        'zip': b'PK\x03\x04',
        '7z':  b'7z\xBC\xAF\x27\x1C',
        'rar': b'Rar!\x1A\x07',
        'tar': b'ustar',
    }

    @staticmethod
    def detect_format(file_path: str) -> Optional[str]:
        """
        Attempt to detect format by reading enough bytes for each signature.
        We also read at least 300 bytes to handle checking for 'ustar' at offset 257.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(300)  # Enough to detect various signatures

                # ZIP
                if data.startswith(ArchiveFormat.SIGNATURES['zip']):
                    return 'zip'
                # 7z
                if data.startswith(ArchiveFormat.SIGNATURES['7z']):
                    return '7z'
                # RAR
                if data.startswith(ArchiveFormat.SIGNATURES['rar']):
                    return 'rar'
                # Additional check for TAR at offset 257
                if len(data) >= 262 and data[257:262] == b'ustar':
                    return 'tar'

        except Exception:
            logging.exception(f"Error in detect_format for {file_path}")
            return None

        return None


class ZipAutoRepair:
    """
    A class that auto-repairs ZIP, 7z, and RAR archives by attempting
    different repair strategies (e.g., reconstructing headers, decompress-recompress, etc.).
    """

    def __init__(self, backup_dir: str = None):
        self.backup_dir = backup_dir or tempfile.gettempdir()
        self.repair_log = {}

        # Now we define dictionary references to newly implemented methods:
        self.repair_strategies = {
            'zip': self._repair_zip,
            '7z': self._repair_7z,
            'rar': self._repair_rar
        }

    def create_backup(self, file_path: str) -> str:
        """Create a backup of the original file before repair attempts."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(
            self.backup_dir,
            f"{Path(file_path).stem}_backup_{timestamp}{Path(file_path).suffix}"
        )
        try:
            shutil.copy2(file_path, backup_path)
            logging.info(f"Created backup at: {backup_path}")
            return backup_path
        except Exception:
            logging.exception("Failed to create backup")
            raise ZipRepairError("Backup creation failed")

    # -------------------------------------------------
    # ZIP: Single entry point to a "comprehensive" repair
    # -------------------------------------------------
    def repair_zip(self, file_path: str) -> bool:
        """
        Attempt to repair a corrupted zip file with multiple strategies.
        Each strategy is tried in turn, stopping if any succeed.
        """
        backup_path = self.create_backup(file_path)
        self.repair_log[file_path] = {"attempts": [], "successful": False}

        repair_methods = [
            self._repair_method_header_fix,
            self._repair_method_repack,
            self._repair_method_stream_repair,
            self._repair_method_deep_scan,
            self._repair_method_decompress_recompress,
            self._repair_method_central_directory
        ]

        for method in repair_methods:
            try:
                if method(file_path):
                    self.repair_log[file_path]["successful"] = True
                    self.repair_log[file_path]["attempts"].append({
                        "method": method.__name__,
                        "status": "Success",
                        "timestamp": datetime.now().isoformat()
                    })
                    self._save_repair_log()
                    return True
            except Exception as e:
                logging.exception(f"Repair method {method.__name__} raised an exception.")
                self.repair_log[file_path]["attempts"].append({
                    "method": method.__name__,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
                # Restore from backup for next attempt
                try:
                    shutil.copy2(backup_path, file_path)
                except Exception:
                    logging.exception("Failed to restore backup during ZIP repair loop.")

        self._save_repair_log()
        return False

    # -------------------------------------------------
    # Methods for dictionary-based calls: _repair_zip, ...
    # -------------------------------------------------
    def _repair_zip(self, file_path: str) -> bool:
        """
        Called from self.repair_strategies['zip'].
        Uses the advanced 'repair_zip' logic defined above.
        """
        return self.repair_zip(file_path)

    def _repair_7z(self, file_path: str) -> bool:
        """
        Attempt to repair a 7z file by:
         1) Creating a backup
         2) Extracting all files into a temp dir
         3) Re-compressing them into a new 7z
         4) Replacing the original if successful
        """
        if not py7zr:
            logging.error("Cannot repair 7z: py7zr not installed.")
            return False

        backup_path = self.create_backup(file_path)
        try:
            temp_dir = tempfile.mkdtemp()
            # Step 1: Attempt to extract
            with py7zr.SevenZipFile(file_path, 'r') as archive:
                archive.extractall(temp_dir)

            # Step 2: Re-compress into a new .7z
            new_path = file_path + '.new.7z'
            with py7zr.SevenZipFile(new_path, 'w') as new_archive:
                for root, dirs, files in os.walk(temp_dir):
                    for each_file in files:
                        full_path = os.path.join(root, each_file)
                        arcname = os.path.relpath(full_path, temp_dir)
                        new_archive.write(full_path, arcname)

            # Step 3: Replace original
            shutil.move(new_path, file_path)
            # Optional: verify integrity. We'll do a simple check:
            if self._verify_7z(file_path):
                logging.info(f"7z repair successful: {file_path}")
                return True
            else:
                logging.error("7z re-compression produced an invalid archive.")
                # revert from backup
                shutil.copy2(backup_path, file_path)
                return False
        except Exception as e:
            logging.exception("7z repair failed.")
            # revert from backup
            try:
                shutil.copy2(backup_path, file_path)
            except Exception:
                logging.exception("Failed to restore backup after 7z repair attempt.")
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _repair_rar(self, file_path: str) -> bool:
        """
        Attempt to repair a RAR file by:
         1) Creating a backup
         2) Extracting all files into a temp dir
         3) Re-compressing them into a new RAR (if rarfile supports writing)
         4) Replacing the original if successful
        """
        if not rarfile:
            logging.error("Cannot repair RAR: 'rarfile' not installed.")
            return False

        backup_path = self.create_backup(file_path)
        try:
            temp_dir = tempfile.mkdtemp()
            # Step 1: Attempt to extract
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(temp_dir)

            # Step 2: Re-compress into a new .rar
            # 'rarfile' does not provide an official "write" or "create" method,
            # so we either need external calls (like `patoolib` or the official RAR)
            # or fallback. We'll do a patool-based approach if patoolib is installed.
            if patoolib:
                new_path = file_path + '.new.rar'
                try:
                    patoolib.create_archive(new_path, (temp_dir,), program="rar")
                    # Step 3: Replace original
                    shutil.move(new_path, file_path)
                    # Optional: verify. We'll do a simple open test:
                    if self._verify_rar(file_path):
                        logging.info(f"RAR repair successful: {file_path}")
                        return True
                    else:
                        logging.error("RAR re-compression produced an invalid archive.")
                        shutil.copy2(backup_path, file_path)
                        return False
                except Exception:
                    logging.exception("Error re-compressing RAR using patoolib.")
                    shutil.copy2(backup_path, file_path)
                    return False
            else:
                # patoolib not installed. We cannot re-compress automatically.
                # We’ll at least confirm we can extract successfully, i.e. the backup is good.
                logging.error("Cannot re-compress RAR: patoolib not installed.")
                shutil.copy2(backup_path, file_path)
                return False

        except Exception:
            logging.exception("RAR repair failed.")
            try:
                shutil.copy2(backup_path, file_path)
            except Exception:
                logging.exception("Failed to restore backup after RAR repair attempt.")
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # -------------------------------------------------
    # Additional "verify" methods for 7z and rar
    # -------------------------------------------------
    def _verify_7z(self, file_path: str) -> bool:
        """A quick check to see if we can open and list a 7z file."""
        if not py7zr:
            return False
        try:
            with py7zr.SevenZipFile(file_path, 'r') as test_sz:
                test_sz.getnames()  # attempt to list
            return True
        except Exception:
            logging.exception("7z verification failed.")
            return False

    def _verify_rar(self, file_path: str) -> bool:
        """A quick check to see if we can open and list a RAR file."""
        if not rarfile:
            return False
        try:
            with rarfile.RarFile(file_path) as test_rar:
                test_rar.namelist()  # attempt to list
            return True
        except Exception:
            logging.exception("RAR verification failed.")
            return False

    # -------------------------------------------------
    # Methods for repairing password-protected zips
    # -------------------------------------------------
    def unlock_zip(self, file_path: str, password_list: List[str]) -> Optional[str]:
        """
        Attempt to unlock a password-protected ZIP file using a list of passwords.
        Returns the password if successful, else None.
        """
        if not pyzipper:
            logging.error("pyzipper not installed; cannot unlock password-protected ZIP files.")
            raise ZipUnlockError("pyzipper library is required for unlocking ZIP files.")

        try:
            with pyzipper.AESZipFile(file_path) as z:
                for password in password_list:
                    try:
                        z.pwd = password.encode('utf-8')
                        # Attempt to read the first file to check password
                        z.testzip()
                        logging.info(f"Successfully unlocked ZIP with password: {password}")
                        return password
                    except RuntimeError:
                        logging.warning(f"Incorrect password: {password}")
                        continue
            logging.error("Failed to unlock ZIP file with provided password list.")
            return None
        except Exception as e:
            logging.exception("An error occurred while attempting to unlock the ZIP file.")
            raise ZipUnlockError(str(e))

    def repair_and_unlock_zip(self, file_path: str, password_list: List[str]) -> bool:
        """
        Attempt to repair and unlock a password-protected ZIP file.
        """
        # First, attempt to repair the ZIP
        if not self.repair_zip(file_path):
            logging.error("Repairing the ZIP file failed.")
            return False

        # Check if the ZIP is password-protected
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                try:
                    z.namelist()  # if it fails due to a password, we handle
                except RuntimeError:
                    logging.info("ZIP file is password-protected. Attempting to unlock.")
                    password = self.unlock_zip(file_path, password_list)
                    if password:
                        # Re-save the ZIP with the found password
                        self.save_unlocked_zip(file_path, password)
                        return True
                    else:
                        logging.error("Failed to unlock the ZIP file.")
                        return False
        except Exception:
            logging.exception("Error while checking ZIP password protection.")
            return False

        # If no password needed or no error, we’re good
        return True

    def save_unlocked_zip(self, file_path: str, password: str) -> bool:
        """
        Save an unlocked version of the ZIP file using the discovered password.
        """
        try:
            with pyzipper.AESZipFile(file_path, 'r') as z:
                z.pwd = password.encode('utf-8')
                unlocked_path = file_path + '.unlocked.zip'
                with pyzipper.AESZipFile(unlocked_path, 'w') as unlocked_zip:
                    for item in z.infolist():
                        data = z.read(item.filename)
                        unlocked_zip.writestr(item, data)
            # Replace the original file with the unlocked version
            shutil.move(unlocked_path, file_path)
            logging.info(f"Unlocked ZIP saved: {file_path}")
            return True
        except Exception:
            logging.exception("Failed to save the unlocked ZIP file.")
            return False

    # -------------------------------------------------
    # The main internal ZIP repair sub-methods
    # -------------------------------------------------
    def _repair_method_header_fix(self, file_path: str) -> bool:
        """Attempt to repair ZIP header by trimming data before PK header."""
        try:
            with open(file_path, 'rb+') as f:
                data = f.read()
                if not data.startswith(b'PK\x03\x04'):
                    zip_start = data.find(b'PK\x03\x04')
                    if zip_start != -1:
                        f.seek(0)
                        f.write(data[zip_start:])
                        f.truncate()
                        return self._verify_zip(file_path)
            return False
        except Exception:
            logging.exception("Header fix failed")
            return False

    def _repair_method_repack(self, file_path: str) -> bool:
        """Attempt to repair by repacking valid entries into a fresh ZIP."""
        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(file_path, 'r') as source_zip:
                valid_files = []
                for item in source_zip.filelist:
                    try:
                        source_zip.extract(item, temp_dir)
                        valid_files.append(os.path.join(temp_dir, item.filename))
                    except Exception:
                        logging.warning(f"Skipping a corrupted file: {item.filename}")
                        continue

            if valid_files:
                with zipfile.ZipFile(file_path, 'w') as new_zip:
                    for vf in valid_files:
                        arcname = os.path.relpath(vf, temp_dir)
                        new_zip.write(vf, arcname)
                return self._verify_zip(file_path)
            return False
        except Exception:
            logging.exception("Repack method failed")
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _repair_method_stream_repair(self, file_path: str) -> bool:
        """Attempt to repair by streaming and validating chunks (very naive)."""
        temp_path = file_path + '.tmp'
        chunk_size = 1024 * 1024  # 1MB chunks

        try:
            with open(file_path, 'rb') as source, open(temp_path, 'wb') as target:
                while True:
                    chunk = source.read(chunk_size)
                    if not chunk:
                        break
                    cleaned_chunk = self._clean_chunk(chunk)
                    if cleaned_chunk:
                        target.write(cleaned_chunk)
            shutil.move(temp_path, file_path)
            return self._verify_zip(file_path)
        except Exception:
            logging.exception("Stream repair failed")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False

    def _repair_method_deep_scan(self, file_path: str) -> bool:
        """Deep scan and reconstruction of ZIP file by searching 'PK\\x03\\x04'."""
        temp_path = file_path + '.reconstructed'
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            pk_positions = []
            pos = 0
            while True:
                pos = data.find(b'PK\x03\x04', pos)
                if pos == -1:
                    break
                pk_positions.append(pos)
                pos += 4

            if not pk_positions:
                return False

            with open(temp_path, 'wb') as wf:
                for start in pk_positions:
                    try:
                        next_start = data.find(b'PK\x03\x04', start + 4)
                        chunk = data[start:next_start] if next_start != -1 else data[start:]
                        if self._validate_zip_chunk(chunk):
                            wf.write(chunk)
                    except Exception:
                        logging.exception("Error reconstructing chunk in deep scan.")
                        continue

            if os.path.getsize(temp_path) > 0:
                shutil.move(temp_path, file_path)
                return self._verify_zip(file_path)
            return False
        except Exception:
            logging.exception("Deep scan failed")
            return False
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def _repair_method_decompress_recompress(self, file_path: str) -> bool:
        """Attempt repair by full decompression and recompression."""
        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                z.extractall(temp_dir)

            new_path = file_path + '.new'
            with zipfile.ZipFile(new_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
                for root, _, files in os.walk(temp_dir):
                    for f_ in files:
                        full_path = os.path.join(root, f_)
                        arcname = os.path.relpath(full_path, temp_dir)
                        z.write(full_path, arcname)

            shutil.move(new_path, file_path)
            return self._verify_zip(file_path)
        except Exception:
            logging.exception("Decompress/recompress method failed")
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _repair_method_central_directory(self, file_path: str) -> bool:
        """Attempt to rebuild the central directory by scanning local file headers."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            entries = []
            pos = 0
            while True:
                pos = data.find(b'PK\x03\x04', pos)
                if pos == -1:
                    break
                try:
                    header = data[pos:pos+30]
                    name_length = struct.unpack('<H', header[26:28])[0]
                    extra_length = struct.unpack('<H', header[28:30])[0]
                    file_name = data[pos+30:pos+30+name_length]

                    entries.append({
                        'offset': pos,
                        'header': header,
                        'name': file_name,
                        'name_length': name_length,
                        'extra_length': extra_length
                    })
                except Exception:
                    logging.exception("Error reading local file header in central directory repair.")
                pos += 4

            if not entries:
                return False

            central_dir = bytearray()
            for entry in entries:
                central_dir.extend(b'PK\x01\x02')
                central_dir.extend(entry['header'][4:])
                central_dir.extend(struct.pack('<L', entry['offset']))
                central_dir.extend(entry['name'])

            new_path = file_path + '.rebuilt'
            with open(new_path, 'wb') as wf:
                wf.write(data)
                wf.write(central_dir)
                wf.write(b'PK\x05\x06')  # End of central directory
                # We do a simplified approach. Some additional fields might be needed in real usage:
                wf.write(struct.pack('<HHLLH',
                                     0, 0,
                                     len(entries), len(entries),
                                     len(central_dir),
                                     len(data)))

            shutil.move(new_path, file_path)
            return self._verify_zip(file_path)
        except Exception:
            logging.exception("Central directory repair failed")
            return False

    # -------------------------------------------------
    # Utility chunk cleaning
    # -------------------------------------------------
    @staticmethod
    def _clean_chunk(chunk: bytes) -> bytes:
        """Clean chunk data if needed. In a production version, you might do more advanced checks."""
        return chunk

    @staticmethod
    def _validate_zip_chunk(chunk: bytes) -> bool:
        """Validate if a chunk contains valid ZIP data (very naive)."""
        try:
            return (
                len(chunk) >= 4
                and chunk.startswith(b'PK\x03\x04')
                and (zlib.crc32(chunk) & 0xFFFFFFFF) != 0
            )
        except Exception:
            logging.exception("Zip chunk validation failed.")
            return False

    @staticmethod
    def _verify_zip(file_path: str) -> bool:
        """Verify if the ZIP file is valid by opening and test-reading it."""
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                result = z.testzip()
                return result is None
        except Exception:
            logging.exception(f"Verification of repaired ZIP failed for {file_path}")
            return False

    def _save_repair_log(self):
        """Save repair log to file"""
        log_path = os.path.join(self.backup_dir, 'zip_repair_log.json')
        try:
            with open(log_path, 'w') as f:
                json.dump(self.repair_log, f, indent=2)
        except Exception:
            logging.exception("Failed to save repair log.")


class ZipProcessor:
    """
    Orchestrates the detection, repair, and extraction of various archive files (ZIP, 7z, RAR, TAR).
    Provides fallback extraction methods for ZIP.
    """
    def __init__(self, max_retries: int = 3, timeout: int = 30):
        self.max_retries = max_retries
        self.timeout = timeout
        self.failed_files: List[str] = []
        self.processed_files: Dict[str, bool] = {}
        self.repair_tool = ZipAutoRepair()

        # Map archive formats to their “process” methods
        self.supported_formats = {
            'zip': self._process_zip,
            '7z': self._process_7z,
            'rar': self._process_rar,
            'tar': self._process_tar
        }

    def process_archive(self, file_path: str, output_dir: str) -> bool:
        """Process any supported archive format by detection, repair if needed, and extraction."""
        archive_format = ArchiveFormat.detect_format(file_path)
        if not archive_format:
            logging.error(f"Unsupported or invalid archive format: {file_path}")
            return False

        processor = self.supported_formats.get(archive_format)
        if not processor:
            logging.error(f"No processor available for format: {archive_format}")
            return False

        return processor(file_path, output_dir)

    # --------------------------
    # ZIP Processing
    # --------------------------
    def _process_zip(self, file_path: str, output_dir: str) -> bool:
        return self.process_zip_file(file_path, output_dir)

    def process_zip_file(self, zip_path: str, output_dir: str) -> bool:
        """Enhanced zip file processing with repair, unlock, and fallback extraction strategies."""
        if not os.path.exists(zip_path):
            logging.error(f"Zip file not found: {zip_path}")
            return False

        # Integrity check
        if not verify_file_integrity(zip_path):
            logging.warning(f"Zip file integrity check failed, attempting repair: {zip_path}")
            if not self.repair_tool.repair_zip(zip_path):
                logging.error("Zip file repair failed")
                return False
            else:
                logging.info("Zip file successfully repaired")

        # Check if ZIP is password-protected
        if self.is_zip_password_protected(zip_path):
            logging.info(f"Zip file is password-protected: {zip_path}")
            # Define a list of potential passwords or load from a file
            password_list = self.load_password_list()
            if not password_list:
                logging.error("No passwords provided for unlocking.")
                return False

            password = self.repair_tool.unlock_zip(file_path=zip_path, password_list=password_list)
            if password:
                logging.info("Successfully unlocked the ZIP file.")
            else:
                logging.error("Failed to unlock the password-protected ZIP file.")
                return False

        # Attempt extraction with fallback methods
        try:
            # First attempt: Standard extraction
            self._standard_extraction(zip_path, output_dir)
        except Exception:
            logging.exception("Standard extraction failed; trying fallback methods.")
            # Fallback 1: Single-file extraction
            try:
                self._single_file_extraction(zip_path, output_dir)
            except Exception:
                logging.exception("Single-file extraction failed; trying chunk-based extraction.")
                # Fallback 2: Chunk-based extraction
                try:
                    self._chunk_based_extraction(zip_path, output_dir)
                except Exception:
                    logging.exception("All extraction methods failed.")
                    return False

        self._report_processing_results()
        return len(self.failed_files) == 0

    def is_zip_password_protected(self, zip_path: str) -> bool:
        """Check if a ZIP file is password-protected by scanning flag_bits."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                for zinfo in z.infolist():
                    # If the 'flag_bits' has bit 0 set => password protected
                    if zinfo.flag_bits & 0x1:
                        return True
            return False
        except Exception:
            logging.exception("Failed to determine if ZIP is password-protected.")
            return False

    def load_password_list(self) -> List[str]:
        """Load a list of passwords from a file named 'passwords.txt' in the same directory."""
        password_list = []
        try:
            # Adjust path if needed. This is a default approach:
            pass_file = os.path.join(os.getcwd(), 'passwords.txt')
            with open(pass_file, 'r', encoding='utf-8') as f:
                for line in f:
                    password_list.append(line.strip())
        except Exception:
            logging.exception("Failed to load password list.")
        return password_list

    def _standard_extraction(self, zip_path: str, output_dir: str) -> None:
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(output_dir)

    def _extract_single_file(self, z: zipfile.ZipFile, file_info: zipfile.ZipInfo, output_dir: str) -> None:
        try:
            with error_handler(f"extracting {file_info.filename}", skip_on_error=True):
                z.extract(file_info, output_dir)
                self.processed_files[file_info.filename] = True
        except Exception:
            self.failed_files.append(file_info.filename)
            logging.exception(f"Failed to extract {file_info.filename}")

    def _single_file_extraction(self, zip_path: str, output_dir: str) -> None:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for file_info in z.infolist():
                for retry in range(self.max_retries):
                    try:
                        with error_handler(f"extracting {file_info.filename}", skip_on_error=True):
                            z.extract(file_info, output_dir)
                            self.processed_files[file_info.filename] = True
                            break
                    except Exception:
                        logging.exception(f"Retry {retry+1}/{self.max_retries} for {file_info.filename}")
                        if retry == self.max_retries - 1:
                            self.failed_files.append(file_info.filename)

    def _chunk_based_extraction(self, zip_path: str, output_dir: str) -> None:
        """
        Read each file in chunk-sized blocks to handle big files or partial corruptions.
        """
        chunk_size = 1024 * 1024  # 1MB
        with zipfile.ZipFile(zip_path, 'r') as z:
            for file_info in z.infolist():
                try:
                    self._extract_in_chunks(z, file_info, output_dir, chunk_size)
                except Exception:
                    self.failed_files.append(file_info.filename)
                    logging.exception(f"Chunk-based extraction failed for {file_info.filename}")

    def _extract_in_chunks(self, z: zipfile.ZipFile, file_info: zipfile.ZipInfo,
                           output_dir: str, chunk_size: int) -> None:
        """Extract a single file from a ZIP in chunk_size increments."""
        target_path = os.path.join(output_dir, file_info.filename)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        with z.open(file_info) as source, open(target_path, 'wb') as target:
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                target.write(chunk)

    def _report_processing_results(self) -> None:
        """Report processing results across the entire extraction process."""
        total_files = len(self.processed_files)
        failed_count = len(self.failed_files)
        success_rate = ((total_files - failed_count) / total_files * 100) if total_files > 0 else 0

        logging.info(f"""
        Processing Summary:
        Total Files: {total_files}
        Successfully Processed: {total_files - failed_count}
        Failed: {failed_count}
        Success Rate: {success_rate:.2f}%
        """)

    # --------------------------
    # 7z Processing
    # --------------------------
    def _process_7z(self, file_path: str, output_dir: str) -> bool:
        """Process a 7z archive if py7zr is available, else fail."""
        if not py7zr:
            logging.error("py7zr not installed; cannot process 7z files.")
            return False
        # Attempt to see if the file even opens
        if not verify_file_integrity(file_path):
            # Attempt a basic repair
            logging.info(f"Attempting 7z repair: {file_path}")
            repaired = self.repair_tool.repair_strategies['7z'](file_path)
            if not repaired:
                logging.error("7z file repair failed.")
                return False

        try:
            with py7zr.SevenZipFile(file_path, 'r') as sz:
                sz.extractall(output_dir)
            return True
        except Exception:
            logging.exception("Error processing 7z file")
            return False

    # --------------------------
    # RAR Processing
    # --------------------------
    def _process_rar(self, file_path: str, output_dir: str) -> bool:
        """Process a RAR archive if rarfile is available, else fail."""
        if not rarfile:
            logging.error("rarfile not installed; cannot process RAR files.")
            return False
        if not verify_file_integrity(file_path):
            logging.info(f"Attempting RAR repair: {file_path}")
            repaired = self.repair_tool.repair_strategies['rar'](file_path)
            if not repaired:
                logging.error("RAR file repair failed.")
                return False

        try:
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(output_dir)
            return True
        except Exception:
            logging.exception("Error processing RAR file")
            return False

    # --------------------------
    # TAR Processing
    # --------------------------
    def _process_tar(self, file_path: str, output_dir: str) -> bool:
        """Process a TAR archive if patoolib is available, else fail."""
        if not patoolib:
            logging.error("patoolib not installed; cannot process TAR (via patoolib).")
            return False
        # We'll trust that a basic TAR doesn't need "repair" for now
        try:
            patoolib.extract_archive(file_path, outdir=output_dir)
            return True
        except Exception:
            logging.exception("Error processing TAR file")
            return False

    # --------------------------
    # Additional Feature:
    #  "Chunk" a single large ZIP into multiple parts
    # --------------------------
    def chunk_zip_file(self, zip_path: str, chunk_size_gib: int) -> List[str]:
        """Enhanced zip file chunking with verification."""
        chunk_paths = []
        chunk_size_bytes = chunk_size_gib * (1024 ** 3)
        base_name = os.path.basename(zip_path)
        base_dir = os.path.dirname(zip_path)

        if not verify_file_integrity(zip_path):
            raise ZipProcessingError("Source file integrity check failed")

        try:
            with open(zip_path, 'rb') as f:
                chunk_number = 0
                while True:
                    chunk = f.read(chunk_size_bytes)
                    if not chunk:
                        break

                    chunk_file_name = f"{base_name}.part{chunk_number:03d}"
                    chunk_file_path = os.path.join(base_dir, chunk_file_name)

                    with error_handler(f"writing chunk {chunk_number}"):
                        with open(chunk_file_path, 'wb') as chunk_file:
                            chunk_file.write(chunk)

                        if verify_file_integrity(chunk_file_path):
                            chunk_paths.append(chunk_file_path)
                            logging.info(f"Successfully created and verified chunk: {chunk_file_name}")
                        else:
                            raise ZipProcessingError(f"Chunk verification failed: {chunk_file_name}")

                    chunk_number += 1

        except Exception:
            logging.exception("Failed to chunk file; cleaning up partial chunks.")
            # Cleanup partial chunks
            for path_ in chunk_paths:
                try:
                    os.remove(path_)
                except Exception:
                    logging.exception(f"Failed to cleanup chunk {path_}")
            raise

        return chunk_paths

    # --------------------------
    # Optional parallel chunk processing example
    # --------------------------
    def _parallel_chunk_processing(self, file_path: str, chunk_size: int = 1024 * 1024) -> None:
        """Process large files in parallel chunks (example usage)."""
        with ThreadPoolExecutor() as executor:
            futures = []
            offset = 0
            file_size = os.path.getsize(file_path)

            while offset < file_size:
                chunk_end = min(offset + chunk_size, file_size)
                futures.append(executor.submit(
                    self._process_chunk, file_path, offset, chunk_end
                ))
                offset = chunk_end

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    logging.exception("Chunk processing error")

    def _process_chunk(self, file_path: str, start: int, end: int) -> None:
        """Process a single chunk of data."""
        try:
            with open(file_path, 'rb') as f:
                f.seek(start)
                chunk = f.read(end - start)
                self._validate_and_clean_chunk(chunk)
        except Exception:
            logging.exception(f"Error processing chunk {start}-{end}")
            raise

    def _validate_and_clean_chunk(self, chunk: bytes) -> bool:
        """Validate and/or clean chunk data if necessary."""
        try:
            if len(chunk) < 4:
                return False
            # Attempt to decompress if compressed
            try:
                zlib.decompress(chunk, -zlib.MAX_WBITS)
                return True
            except zlib.error:
                # If not compressed, do a simple check on the first 1KB
                return all(b > 0x08 for b in chunk[:1024])
        except Exception:
            logging.exception("Error validating chunk")
            return False


# -------------------------------
# Windows Rounded Window
# -------------------------------
if sys.platform.startswith('win'):
    class WindowsRoundedWindow:
        def __init__(self, root, width, height, radius):
            self.root = root
            self.width = width
            self.height = height
            self.radius = radius
            self._set_window_style()
            self._create_rounded_corners()

        def _set_window_style(self):
            """Set window style to appear in the taskbar."""
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            GWL_EXSTYLE = -20
            WS_EX_APPWINDOW = 0x00040000
            WS_EX_TOOLWINDOW = 0x00000080

            exstyle = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            exstyle |= WS_EX_APPWINDOW
            exstyle &= ~WS_EX_TOOLWINDOW
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, exstyle)
            ctypes.windll.user32.ShowWindow(hwnd, 5)  # SW_SHOW

        def _create_rounded_corners(self):
            """Create rounded corners using the Windows API."""
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            CreateRoundRectRgn = ctypes.windll.gdi32.CreateRoundRectRgn
            SetWindowRgn = ctypes.windll.user32.SetWindowRgn

            region = CreateRoundRectRgn(0, 0, self.width, self.height, self.radius, self.radius)
            SetWindowRgn(hwnd, region, True)
            # OS takes ownership of region, so no DeleteObject needed.


# -------------------------------
# Tkinter GUI for ZIPHero
# -------------------------------
class SimpleZipGUI:
    """
    A simple dragable, borderless Tkinter GUI for ZIPHero, featuring:
    - Title bar with custom close button
    - Rounded corners on Windows
    - File selection, output folder selection
    - Basic status updates
    """
    def __init__(self, root):
        self.root = root
        self.root.title("ZIPhero")
        self.root.geometry("300x300")
        self.root.resizable(False, False)

        # Remove window decorations
        self.root.overrideredirect(True)

        # Configure window transparency (for rounded corners) if on Windows
        if sys.platform.startswith('win'):
            self.rounded_window = WindowsRoundedWindow(self.root, 300, 300, 20)

        # Make window draggable
        self._offsetx = 0
        self._offsety = 0

        self.output_var = tk.StringVar()
        self.zip_files = set()
        self.loading_dots = 0
        self.license_url = "https://github.com/JMitander/ZIPhero/blob/main/LICENSE"

        self.setup_gui()
        self.update_loading_dots()

    def setup_gui(self):
        # Create a canvas to handle background
        self.canvas = tk.Canvas(self.root, bg='black', highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)

        # Title bar frame
        title_frame = tk.Frame(self.canvas, bg='black', height=30)
        title_frame.place(x=0, y=0, width=300, height=30)

        # Close button
        close_button = tk.Label(
            title_frame,
            text="Exit ✕",
            bg='black',
            fg='red',
            font=('Arial Black', 12, 'bold'),
            cursor='hand2'
        )
        close_button.pack(side='right', padx=10, pady=5)
        close_button.bind('<Button-1>', lambda e: self.root.destroy())

        # Title
        title_label = tk.Label(
            title_frame,
            text="ZIPHero by JMitander",
            bg='black',
            fg='#0066cc',
            font=('Arial Black', 8, 'bold')
        )
        title_label.pack(side='left', padx=10)

        # Make title bar draggable
        title_frame.bind('<Button-1>', self.start_move)
        title_frame.bind('<B1-Motion>', self.do_move)
        self.canvas.bind('<Button-1>', self.start_move)
        self.canvas.bind('<B1-Motion>', self.do_move)

        # Main content frame
        content_frame = tk.Frame(self.canvas, bg='#222222')
        content_frame.place(x=20, y=40, width=260, height=220)

        # Files list with a 2px highlight border
        list_frame = tk.Frame(
            content_frame,
            bg='#222222',
            highlightbackground='#444444',
            highlightthickness=2,
            bd=0
        )
        list_frame.pack(fill='both', expand=True, pady=(0, 10))

        self.files_list = tk.Listbox(
            list_frame,
            bg='#333333',
            fg='white',
            selectmode=tk.MULTIPLE,
            height=2,
            font=('Arial', 10),
            bd=0,
            highlightthickness=0
        )
        self.files_list.pack(fill='both', expand=True, padx=5, pady=5)

        # Button styling
        button_style = {
            'font': ('Arial Black', 10),
            'width': 20,
            'height': 1,
            'bg': 'white',
            'fg': 'black',
            'bd': 0,
            'relief': 'flat',
            'cursor': 'hand2'
        }

        # Buttons
        buttons_frame = tk.Frame(content_frame, bg='#222222')
        buttons_frame.pack(pady=5)

        self.output_button = tk.Button(
            buttons_frame,
            text="Select Output",
            command=self.select_output,
            **button_style
        )
        self.output_button.pack(pady=2)

        self.select_button = tk.Button(
            buttons_frame,
            text="Select Archive(s)",
            command=self.add_zip_files,
            **button_style
        )
        self.select_button.pack(pady=2)

        self.unzip_button = tk.Button(
            buttons_frame,
            text="Extract",
            command=self.process_files,
            **button_style
        )
        self.unzip_button.pack(pady=2)

        # Status label
        self.status_label = tk.Label(
            content_frame,
            text="Ready...",
            bg='#222222',
            fg='white',
            font=('Consolas', 8),
            wraplength=240,
            height=2
        )
        self.status_label.pack(pady=5)

        # License link at the bottom
        license_label = tk.Label(
            self.canvas,
            text="License",
            bg='black',
            fg='#666666',
            font=('Arial', 8),
            cursor='hand2'
        )
        license_label.place(relx=0.5, rely=0.95, anchor='center')
        license_label.bind('<Button-1>', lambda e: webbrowser.open(self.license_url))
        license_label.bind(
            '<Enter>',
            lambda e: license_label.configure(fg='#888888', font=('Arial', 8, 'underline'))
        )
        license_label.bind(
            '<Leave>',
            lambda e: license_label.configure(fg='#666666', font=('Arial', 8))
        )

    def start_move(self, event):
        """Begin window drag"""
        self._offsetx = event.x
        self._offsety = event.y

    def do_move(self, event):
        """Handle window dragging"""
        x = self.root.winfo_pointerx() - self._offsetx
        y = self.root.winfo_pointery() - self._offsety
        self.root.geometry(f'+{x}+{y}')

    def update_loading_dots(self):
        """Update the loading dots animation without blocking the GUI."""
        if hasattr(self, 'status_label'):
            current_text = self.status_label.cget('text').rstrip('.')
            # Animate only if not the default "Ready..."
            if current_text and current_text != "Ready...":
                self.loading_dots = (self.loading_dots + 1) % 4
                dots = '.' * self.loading_dots
                self.status_label.config(text=f"{current_text}{dots}")
        self.root.after(500, self.update_loading_dots)

    def update_status(self, message: str):
        """Update status text"""
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def add_zip_files(self):
        files = filedialog.askopenfilenames(
            title="Select Archive(s)",
            filetypes=[("Archive files", "*.zip *.7z *.rar *.tar *.gz *.bz2 *.xz *.lz *.z *.iso")]
        )
        for file_ in files:
            self.zip_files.add(file_)
        self.update_files_list()

    def update_files_list(self):
        self.files_list.delete(0, tk.END)
        for file_ in sorted(self.zip_files):
            self.files_list.insert(tk.END, os.path.basename(file_))

    def select_output(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_var.set(folder)

    def process_files(self):
        if not self.zip_files:
            self.update_status("Please select at least one archive!")
            return

        if not self.output_var.get():
            self.update_status("Please select an output folder!")
            return

        processor = ZipProcessor(max_retries=3, timeout=30)
        output_dir = self.output_var.get()

        try:
            os.makedirs(output_dir, exist_ok=True)
            backup_dir = os.path.join(output_dir, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            processor.repair_tool.backup_dir = backup_dir

            for archive_file in self.zip_files:
                self.update_status(f"Processing: {os.path.basename(archive_file)}")
                # Attempt to detect format, possibly repair, and extract
                if processor.process_archive(archive_file, output_dir):
                    self.update_status(f"Success: {os.path.basename(archive_file)}")
                else:
                    self.update_status(f"Issues encountered: {os.path.basename(archive_file)}")

            self.update_status("All selected archives processed!")
        except Exception:
            logging.exception("Error in GUI processing")
            self.update_status("A critical error occurred. Check logs for details.")


# ------------------------------------------
# Main Entry Point: Run GUI or CLI
# ------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) == 1:
        # GUI Mode
        root = tk.Tk()
        # Make window appear on top initially
        root.attributes('-topmost', True)
        app = SimpleZipGUI(root)
        # Disable topmost after showing
        root.after_idle(root.attributes, '-topmost', False)
        root.mainloop()
    else:
        # Command Line Mode
        zip_file_path = sys.argv[1] if len(sys.argv) > 1 else "path/to/your/zipfile.zip"
        output_directory = sys.argv[2] if len(sys.argv) > 2 else "path/to/extracted/files"
        chunk_size_gib = int(sys.argv[3]) if len(sys.argv) > 3 else 5

        processor = ZipProcessor(max_retries=3, timeout=30)
        try:
            os.makedirs(output_directory, exist_ok=True)
            backup_dir = os.path.join(os.path.dirname(zip_file_path), "backups")
            os.makedirs(backup_dir, exist_ok=True)
            processor.repair_tool.backup_dir = backup_dir

            logging.info("Starting extraction with repair/unlock methods...")
            if processor.process_zip_file(zip_file_path, output_directory):
                logging.info("Extraction completed successfully")
            else:
                logging.warning("Extraction completed with some failures")

            logging.info("Starting zip file chunking...")
            chunk_paths = processor.chunk_zip_file(zip_file_path, chunk_size_gib)
            logging.info(f"Successfully created {len(chunk_paths)} chunks")

        except Exception:
            logging.exception("Critical error during processing")
            sys.exit(1)

        logging.info("Processing complete.")
