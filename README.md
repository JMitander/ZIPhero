# ZIPHero Documentation

A powerful ZIP file processor with repair capabilities and user-friendly interface.

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
- Contact: your@email.com

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

