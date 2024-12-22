# ZIPHero Documentation

A powerful ZIP file processor with repair capabilities and user-friendly interface.

# Important Note 🚨🚨
### When running the .exe file for the first time, Windows Defender or other antivirus software may flag it as potentially unsafe. This is a common occurrence with executables created via PyInstaller, especially for smaller developers without a verified code-signing certificate.

### Why This Happens
Antivirus software sometimes misidentifies unsigned applications or compressed executables as threats due to their structure.
Rest assured, ZIPHero is safe to use and contains no malicious code.

### How to Proceed
Allow the application through your antivirus software.
If you're still concerned, review the source code (available on GitHub) and compile it yourself.

## Download Options

- [ZIPHero.py](releases/ZIPHero.py) - Python source code

## Quick Start Guide

### Using Python Source

Requirements:
```bash
Python 10.7+
tkinter (usually included with Python)
```

To run:
```bash
python ZIPHero.py
```

## How to Use

1. Launch ZIPHero
2. Click "Select ZIP File(s)" to choose your ZIP files
3. Click "Browse" to select where to extract files
4. Click "Un-Zip" to start processing

## Features

- 🔄 Automatic ZIP repair
- 📁 Multiple file selection
- 🛡️ Safe extraction
- 🔍 Corrupt file detection
- 💾 Automatic backups
- ⚡ Fast processing

## Common Issues

**"Cannot open file"**
- Check if file is not in use
- Try running as administrator

**"Extraction failed"**
- Program will automatically try to repair
- Check available disk space
- Look in backup folder for original

## Command Line Usage (Python Version)

Advanced users can use command line options:

```bash
python ZIPHero.py <zipfile> <output_dir> <chunk_size>
```

Example:
```bash
python ZIPHero.py myfile.zip extracted 5
```

## Technical Details

- Creates backups before repairs
- Logs all operations
- Multiple repair strategies
- Safe failure handling

## Need Help?

- Check the log file: `zip_processor.log`
- Files are backed up in: `backups` folder
- Contact: john@nordchain.io

## Building from Source

To create your own executable:
```bash
pip install pyinstaller
pyinstaller --onefile --windowed ZIPHero.py
```

## Updates

- v1.0: Initial release

## License

MIT License - See LICENSE file

## Credits

Created by jmitander

