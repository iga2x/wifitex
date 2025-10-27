# Rockyou.txt Wordlist Setup Guide

## Automatic Multi-Wordlist Support Added

WifiteX now automatically tries multiple wordlists in order when cracking passwords, including rockyou.txt!

## How It Works

1. **Primary Wordlist**: The wordlist you specify (or default)
2. **Rockyou.txt**: Automatically detected and used if available
3. **Additional Wordlists**: Other common system wordlists

## Installing Rockyou.txt (Kali Linux)

```bash
# Download and extract rockyou.txt
sudo wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /usr/share/wordlists/rockyou.txt

# Or if you already have it compressed
cd /usr/share/wordlists
sudo gunzip rockyou.txt.gz
```

## Locations Checked Automatically

The system checks these locations in order:
- `/usr/share/wordlists/rockyou.txt` (standard Kali location)
- `/usr/share/wordlists/rockyou.txt.gz` (compressed version)
- `./wordlists/rockyou.txt` (local project directory)
- `rockyou.txt` (current directory)

## Usage

Just run WifiteX normally! If rockyou.txt exists, it will be used automatically:

```bash
# Capture handshake and crack with multiple wordlists
wifitex -i wlan1

# Or manually crack a saved handshake
wifitex --crack -i wlan1
```

## Example Output

When multiple wordlists are used, you'll see:

```
[+] Cracking WPA Handshake: Running hashcat with wordlist-top4800-probable.txt
[+] Trying wordlist: wordlist-top4800-probable.txt
[!] Failed to crack with wordlist-top4800-probable.txt
[+] Trying wordlist: rockyou.txt
[+] Password found using rockyou.txt!
[+] Cracked WPA Handshake PSK: yourpassword123
```

## Benefits

- **Higher Success Rate**: If password isn't in primary wordlist, rockyou.txt is tried
- **Zero Configuration**: Works automatically if rockyou.txt exists
- **No User Intervention**: Tries wordlists in order automatically
- **Better Coverage**: 14+ million passwords in rockyou.txt vs 4800 in default

## Verification

To verify rockyou.txt is being used:

```bash
# Check if file exists
ls -lh /usr/share/wordlists/rockyou.txt

# Should show ~135MB file with 14M+ lines
```

## For Other Wordlists

You can add custom wordlists by:
1. Placing them in one of the checked locations
2. Modifying `get_wordlists()` method in `wifitex/tools/hashcat.py` or `wifitex/tools/aircrack.py`
3. Or specify wordlist directly: `wifitex --dict /path/to/wordlist.txt`
