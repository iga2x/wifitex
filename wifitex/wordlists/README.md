# WifiteX Wordlists Directory

This directory automatically contains all wordlists used for WPA/WPA2 password cracking.

## How It Works

Put your wordlist files (`.txt`, `.lst`, or `.gz`) in this directory and they will be **automatically detected and used** by both CLI and GUI versions of WifiteX.

## Priority Order

1. **Primary wordlist** (specified via `--dict` or Settings)
2. **wordlists in this directory** (`wifitex/wordlists/`) - HIGHEST PRIORITY
3. System wordlists (`/usr/share/wordlists/`)
4. Other common wordlists

## Supported Formats

- `.txt` - Text files (plain wordlists)
- `.lst` - List files
- `.gz` - Gzipped wordlists (auto-extracted)

## Examples

```bash
# Add wordlists to this directory
cp rockyou.txt wifitex/wordlists/
cp my-custom-wordlist.txt wifitex/wordlists/
```

## Auto-Detection

WifiteX automatically:
- ✅ Scans this directory at startup
- ✅ Lists all wordlists in GUI settings dropdown
- ✅ Uses them in "Comprehensive Attack" strategy
- ✅ Shows wordlist name, size, and description in GUI

## Recommended Wordlists

Popular wordlists you can download and place here:

- `rockyou.txt` - 14+ million passwords
- `wordlist-top4800-probable.txt` - Small but effective (included)
- Custom wordlists for specific targets

## Notes

- Files are automatically detected by name - no configuration needed
- Wordlists in this folder have **highest priority** over system wordlists
- Both CLI and GUI use wordlists from this folder automatically

