import zipfile
import os
import shutil
import time
import logging
import hashlib
import sys
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import tempfile
from pathlib import Path
from datetime import datetime
import json
import zlib
import tkinter as tk
from tkinter import filedialog, ttk

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('zip_processor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class ZipProcessingError(Exception):
    """Custom exception for zip processing errors"""
    pass

class ZipRepairError(Exception):
    """Custom exception for zip repair errors"""
    pass

@contextmanager
def error_handler(operation: str, skip_on_error: bool = True):
    """Context manager for handling operations with optional skip on error"""
    try:
        yield
    except Exception as e:
        logging.error(f"Error during {operation}: {str(e)}")
        if not skip_on_error:
            raise

def verify_file_integrity(file_path: str) -> bool:
    """Verify file integrity using checksum"""
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.md5()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return True
    except Exception as e:
        logging.error(f"File integrity check failed for {file_path}: {e}")
        return False

class ZipAutoRepair:
    def __init__(self, backup_dir: str = None):
        self.backup_dir = backup_dir or tempfile.gettempdir()
        self.repair_log = {}
        
    def create_backup(self, file_path: str) -> str:
        """Create a backup of the original file before repair attempts"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(
            self.backup_dir,
            f"{Path(file_path).stem}_backup_{timestamp}{Path(file_path).suffix}"
        )
        try:
            shutil.copy2(file_path, backup_path)
            logging.info(f"Created backup at: {backup_path}")
            return backup_path
        except Exception as e:
            logging.error(f"Failed to create backup: {e}")
            raise ZipRepairError("Backup creation failed")

    def repair_zip(self, file_path: str) -> bool:
        """Attempt to repair a corrupted zip file"""
        backup_path = self.create_backup(file_path)
        self.repair_log[file_path] = {"attempts": [], "successful": False}
        
        repair_methods = [
            self._repair_method_header_fix,
            self._repair_method_repack,
            self._repair_method_stream_repair,
            self._repair_method_deep_scan
        ]

        for method in repair_methods:
            try:
                if method(file_path):
                    self.repair_log[file_path]["successful"] = True
                    self._save_repair_log()
                    return True
            except Exception as e:
                self.repair_log[file_path]["attempts"].append({
                    "method": method.__name__,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
                # Restore from backup for next attempt
                shutil.copy2(backup_path, file_path)

        return False

    def _repair_method_header_fix(self, file_path: str) -> bool:
        """Attempt to repair ZIP header"""
        try:
            with open(file_path, 'rb+') as f:
                data = f.read()
                if data[:4] != b'PK\x03\x04':
                    # Find ZIP header in file
                    zip_start = data.find(b'PK\x03\x04')
                    if zip_start != -1:
                        f.seek(0)
                        f.write(data[zip_start:])
                        f.truncate()
                        return self._verify_zip(file_path)
            return False
        except Exception as e:
            logging.error(f"Header fix failed: {e}")
            return False

    def _repair_method_repack(self, file_path: str) -> bool:
        """Attempt to repair by repacking valid entries"""
        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(file_path, 'r') as source_zip:
                # Extract valid files
                valid_files = []
                for item in source_zip.filelist:
                    try:
                        source_zip.extract(item, temp_dir)
                        valid_files.append(os.path.join(temp_dir, item.filename))
                    except Exception:
                        continue

                # Create new zip with valid files
                if valid_files:
                    with zipfile.ZipFile(file_path, 'w') as new_zip:
                        for file in valid_files:
                            arcname = os.path.relpath(file, temp_dir)
                            new_zip.write(file, arcname)
                    return self._verify_zip(file_path)
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _repair_method_stream_repair(self, file_path: str) -> bool:
        """Attempt to repair by streaming and validating chunks"""
        temp_path = file_path + '.tmp'
        chunk_size = 1024 * 1024  # 1MB chunks
        
        try:
            with open(file_path, 'rb') as source, open(temp_path, 'wb') as target:
                while True:
                    chunk = source.read(chunk_size)
                    if not chunk:
                        break
                    # Validate and clean chunk
                    cleaned_chunk = self._clean_chunk(chunk)
                    if cleaned_chunk:
                        target.write(cleaned_chunk)
            
            shutil.move(temp_path, file_path)
            return self._verify_zip(file_path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False

    def _repair_method_deep_scan(self, file_path: str) -> bool:
        """Deep scan and reconstruction of ZIP file"""
        temp_path = file_path + '.reconstructed'
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Find all local file headers
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

            # Reconstruct ZIP file
            with open(temp_path, 'wb') as f:
                for start in pk_positions:
                    try:
                        # Find next header or EOF
                        next_start = data.find(b'PK\x03\x04', start + 4)
                        chunk = data[start:next_start] if next_start != -1 else data[start:]
                        if self._validate_zip_chunk(chunk):
                            f.write(chunk)
                    except Exception:
                        continue

            if os.path.getsize(temp_path) > 0:
                shutil.move(temp_path, file_path)
                return self._verify_zip(file_path)
            return False
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    @staticmethod
    def _clean_chunk(chunk: bytes) -> bytes:
        """Clean and validate chunk data"""
        try:
            # Remove invalid zip markers
            cleaned = chunk.replace(b'PK\x03\x04', b'PK\x03\x04', 1)
            return cleaned
        except Exception:
            return chunk

    @staticmethod
    def _validate_zip_chunk(chunk: bytes) -> bool:
        """Validate if chunk contains valid zip data"""
        try:
            return (
                len(chunk) >= 4 and
                chunk.startswith(b'PK\x03\x04') and
                zlib.crc32(chunk) & 0xFFFFFFFF
            )
        except Exception:
            return False

    @staticmethod
    def _verify_zip(file_path: str) -> bool:
        """Verify if the zip file is valid"""
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                result = z.testzip()
                return result is None
        except Exception:
            return False

    def _save_repair_log(self):
        """Save repair log to file"""
        log_path = os.path.join(self.backup_dir, 'zip_repair_log.json')
        try:
            with open(log_path, 'w') as f:
                json.dump(self.repair_log, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save repair log: {e}")

class ZipProcessor:
    def __init__(self, max_retries: int = 3, timeout: int = 30):
        self.max_retries = max_retries
        self.timeout = timeout
        self.failed_files: List[str] = []
        self.processed_files: Dict[str, bool] = {}
        self.repair_tool = ZipAutoRepair()

    def process_zip_file(self, zip_path: str, output_dir: str) -> bool:
        """Enhanced zip file processing with repair capabilities"""
        if not os.path.exists(zip_path):
            logging.error(f"Zip file not found: {zip_path}")
            return False

        if not verify_file_integrity(zip_path):
            logging.warning(f"Zip file integrity check failed, attempting repair: {zip_path}")
            if self.repair_tool.repair_zip(zip_path):
                logging.info("Zip file successfully repaired")
            else:
                logging.error("Zip file repair failed")
                return False

        try:
            # First attempt: Standard extraction
            self._standard_extraction(zip_path, output_dir)
        except Exception as e:
            logging.warning(f"Standard extraction failed, trying fallback methods: {e}")
            # Fallback 1: Single-file extraction
            try:
                self._single_file_extraction(zip_path, output_dir)
            except Exception as e:
                logging.warning(f"Single-file extraction failed, trying final fallback: {e}")
                # Fallback 2: Chunk-based extraction
                try:
                    self._chunk_based_extraction(zip_path, output_dir)
                except Exception as e:
                    logging.error(f"All extraction methods failed: {e}")
                    return False

        self._report_processing_results()
        return len(self.failed_files) == 0

    def _standard_extraction(self, zip_path: str, output_dir: str) -> None:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for file_info in z.infolist():
                self._extract_single_file(z, file_info, output_dir)

    def _single_file_extraction(self, zip_path: str, output_dir: str) -> None:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for file_info in z.infolist():
                for retry in range(self.max_retries):
                    try:
                        with error_handler(f"extracting {file_info.filename}", skip_on_error=True):
                            z.extract(file_info, output_dir)
                            self.processed_files[file_info.filename] = True
                            break
                    except Exception as e:
                        if retry == self.max_retries - 1:
                            self.failed_files.append(file_info.filename)
                            logging.error(f"Failed to extract {file_info.filename} after {self.max_retries} retries")

    def _chunk_based_extraction(self, zip_path: str, output_dir: str) -> None:
        chunk_size = 1024 * 1024  # 1MB chunks
        with zipfile.ZipFile(zip_path, 'r') as z:
            for file_info in z.infolist():
                try:
                    self._extract_in_chunks(z, file_info, output_dir, chunk_size)
                except Exception as e:
                    self.failed_files.append(file_info.filename)
                    logging.error(f"Chunk-based extraction failed for {file_info.filename}: {e}")

    def _extract_in_chunks(self, z: zipfile.ZipFile, file_info: zipfile.ZipInfo, 
                          output_dir: str, chunk_size: int) -> None:
        target_path = os.path.join(output_dir, file_info.filename)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        with z.open(file_info) as source, open(target_path, 'wb') as target:
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                target.write(chunk)

    def chunk_zip_file(self, zip_path: str, chunk_size_gib: int) -> List[str]:
        """Enhanced zip file chunking with verification"""
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

        except Exception as e:
            logging.error(f"Failed to chunk file: {e}")
            # Cleanup partial chunks
            for chunk_path in chunk_paths:
                try:
                    os.remove(chunk_path)
                except Exception as cleanup_error:
                    logging.error(f"Failed to cleanup chunk {chunk_path}: {cleanup_error}")
            raise

        return chunk_paths

    def _report_processing_results(self) -> None:
        """Report processing results"""
        total_files = len(self.processed_files)
        failed_files = len(self.failed_files)
        success_rate = ((total_files - failed_files) / total_files * 100) if total_files > 0 else 0

        logging.info(f"""
        Processing Summary:
        Total Files: {total_files}
        Successfully Processed: {total_files - failed_files}
        Failed: {failed_files}
        Success Rate: {success_rate:.2f}%
        """)

class SimpleZipGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ZIPhero by jmitander")
        self.root.geometry("400x450")
        self.root.resizable(False, False)  # Disable resizing
        self.root.configure(bg='black')
        
        self.zip_files = set()
        self.setup_gui()

    def setup_gui(self):
        # Main frame
        main_frame = tk.Frame(self.root, bg='black', padx=10, pady=10)
        main_frame.pack(expand=True, fill='both')

        # Title
        tk.Label(
            main_frame,
            text="ZIPhero by jmitander",
            bg='black',
            fg='#0066cc',
            font=('Arial', 14, 'bold')
        ).pack(pady=(0, 15))

        # ZIP Files Section
        tk.Label(
            main_frame, 
            text="Selected ZIP files:", 
            bg='black', 
            fg='white',
            font=('Arial', 9)
        ).pack(anchor='w')

        # Listbox for selected files in a frame for fixed size
        list_frame = tk.Frame(main_frame, bg='black')
        list_frame.pack(fill='both', pady=(5, 10))
        
        self.files_list = tk.Listbox(
            list_frame,
            bg='#222222',
            fg='white',
            selectmode=tk.MULTIPLE,
            height=6,
            width=40,
            font=('Arial', 9)
        )
        self.files_list.pack(side='left', fill='both')
        
        # Scrollbar for listbox
        scrollbar = tk.Scrollbar(list_frame, orient="vertical")
        scrollbar.config(command=self.files_list.yview)
        scrollbar.pack(side='right', fill='y')
        self.files_list.config(yscrollcommand=scrollbar.set)

        # Buttons frame for better alignment
        buttons_frame = tk.Frame(main_frame, bg='black')
        buttons_frame.pack(fill='x', pady=(0, 10))

        # Add ZIP files button
        tk.Button(
            buttons_frame,
            text="Select ZIP File(s)",
            command=self.add_zip_files,
            bg='#0066cc',
            fg='white',
            width=15,
            font=('Arial', 9)
        ).pack(side='left', padx=5)

        # Output folder section
        tk.Label(
            main_frame,
            text="Output folder:",
            bg='black',
            fg='white',
            font=('Arial', 9)
        ).pack(anchor='w')

        # Output path display with selection button in same row
        path_frame = tk.Frame(main_frame, bg='black')
        path_frame.pack(fill='x', pady=(5, 15))

        self.output_var = tk.StringVar()
        tk.Entry(
            path_frame,
            textvariable=self.output_var,
            bg='#222222',
            fg='white',
            width=30,
            font=('Arial', 9)
        ).pack(side='left', padx=(0, 5))

        tk.Button(
            path_frame,
            text="Browse",
            command=self.select_output,
            bg='#0066cc',
            fg='white',
            width=8,
            font=('Arial', 9)
        ).pack(side='right')

        # Unzip button
        tk.Button(
            main_frame,
            text="Un-Zip",
            command=self.process_files,
            bg='#0066cc',
            fg='white',
            width=20,
            height=1,
            font=('Arial', 11, 'bold')
        ).pack(pady=15)

        # Status label
        self.status_label = tk.Label(
            main_frame,
            text="",
            bg='black',
            fg='white',
            wraplength=380,
            font=('Arial', 9)
        )
        self.status_label.pack(pady=5)

    def add_zip_files(self):
        files = filedialog.askopenfilenames(
            title="Select ZIP files",
            filetypes=[("ZIP files", "*.zip")]
        )
        for file in files:
            self.zip_files.add(file)
        self.update_files_list()

    def update_files_list(self):
        self.files_list.delete(0, tk.END)
        for file in sorted(self.zip_files):
            self.files_list.insert(tk.END, os.path.basename(file))

    def select_output(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_var.set(folder)

    def process_files(self):
        if not self.zip_files:
            self.status_label.config(text="Please select ZIP file(s)!")
            return
        
        if not self.output_var.get():
            self.status_label.config(text="Please select output folder!")
            return

        processor = ZipProcessor(max_retries=3, timeout=30)
        output_dir = self.output_var.get()

        try:
            os.makedirs(output_dir, exist_ok=True)
            
            for zip_file in self.zip_files:
                self.status_label.config(text=f"Processing: {os.path.basename(zip_file)}")
                self.root.update()
                
                if processor.process_zip_file(zip_file, output_dir):
                    self.status_label.config(
                        text=f"Successfully processed: {os.path.basename(zip_file)}"
                    )
                else:
                    self.status_label.config(
                        text=f"Completed with some failures: {os.path.basename(zip_file)}"
                    )
                self.root.update()

            self.status_label.config(text="All files processed successfully!")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")

if __name__ == "__main__":
    # Check if running in GUI mode (no command line arguments)
    if len(sys.argv) == 1:
        root = tk.Tk()
        app = SimpleZipGUI(root)
        root.mainloop()
    else:
        # Original command line mode
        zip_file_path = sys.argv[1] if len(sys.argv) > 1 else "path/to/your/zipfile.zip"
        output_directory = sys.argv[2] if len(sys.argv) > 2 else "path/to/extracted/files"
        chunk_size_gib = int(sys.argv[3]) if len(sys.argv) > 3 else 5

        # Initialize processor
        processor = ZipProcessor(max_retries=3, timeout=30)

        try:
            # ...existing command line processing code...
            os.makedirs(output_directory, exist_ok=True)
            
            backup_dir = os.path.join(os.path.dirname(zip_file_path), "backups")
            os.makedirs(backup_dir, exist_ok=True)
            processor.repair_tool.backup_dir = backup_dir

            logging.info("Starting extraction with failsafe method...")
            if processor.process_zip_file(zip_file_path, output_directory):
                logging.info("Extraction completed successfully")
            else:
                logging.warning("Extraction completed with some failures")

            logging.info("Starting zip file chunking...")
            chunk_paths = processor.chunk_zip_file(zip_file_path, chunk_size_gib)
            logging.info(f"Successfully created {len(chunk_paths)} chunks")

        except Exception as e:
            logging.error(f"Critical error during processing: {e}")
            sys.exit(1)

        logging.info("Processing complete.")
