# Wordlist Auto-Detection System

## Summary

The wordlist system has been updated to **auto-detect ALL wordlists** instead of using fixed lists.

## What Changed

### 1. Created Wordlist Folder
```
wifitex/wordlists/
├── README.md
├── wordlist-top4800-probable.txt
└── (any other wordlist files you add)
```

### 2. Removed Fixed Wordlist Names

**Before:**
```python
'wordlists': ['rockyou', 'wordlist-top4800-probable', 'wifitex', 'sqlmap', 'common']
```

**After:**
```python
# Auto-detects ALL wordlists from wifitex/wordlists/ folder and system
all_wordlists = self.wordlist_manager.get_all_wordlists()
wordlist_paths = list(all_wordlists.keys())  # Uses ALL detected wordlists
```

### 3. GUI Strategy Updates

| Strategy | Before | After |
|----------|--------|-------|
| Fast Attack | Fixed 3 wordlists | Uses **first 3 detected** |
| Comprehensive Attack | Fixed 5 wordlists | Uses **ALL detected wordlists** |
| Router-Focused | Fixed 3 wordlists | Uses **first 5 detected** |

### 4. CLI Auto-Detection

Both `aircrack-ng` and `hashcat` now:
- ✅ Scan `wifitex/wordlists/` folder first
- ✅ Detect ALL `.txt`, `.lst`, `.gz` files
- ✅ Use them automatically in cracking
- ✅ No fixed wordlist names

## How to Use

### Add Wordlists

Simply place files in `wifitex/wordlists/`:

```bash
# Example: Add rockyou.txt
cp rockyou.txt wifitex/wordlists/

# Example: Add custom wordlist
cp my-custom-wordlist.txt wifitex/wordlists/
```

### GUI Usage

1. **Settings Panel** → **Password Cracking Settings**
2. Select **"Comprehensive Attack (All wordlists)"**
3. Enable **"Use Multiple Wordlists"** ✓
4. All detected wordlists will be used automatically!

### CLI Usage

```bash
# Auto-detects and uses all wordlists from wifitex/wordlists/
sudo wifitex --crack

# Or specify a wordlist from the folder
sudo wifitex --crack --dict wifitex/wordlists/my-wordlist.txt
```

## Priority Order

1. **Primary wordlist** (specified with `--dict`)
2. **wifitex/wordlists/** folder (HIGHEST - auto-detected)
3. `/usr/share/wordlists/` (rockyou.txt, etc.)
4. Other system wordlists

## Detection Methods

### GUI
- Scans `wifitex/wordlists/` folder at startup
- Shows all wordlists in dropdown
- Uses all detected wordlists with "Comprehensive Attack"

### CLI
- Scans `wifitex/wordlists/` folder for each cracking attempt
- Uses all detected wordlists in order
- Falls back to system wordlists if folder is empty

## Benefits

✅ **No fixed wordlist names** - removed hardcoded lists
✅ **Auto-detection** - finds all wordlists automatically
✅ **Easy to add** - just drop files in `wifitex/wordlists/`
✅ **Works for both CLI and GUI** - consistent behavior
✅ **Highest priority** - local wordlists tried first
✅ **Scalable** - add as many wordlists as you want

## Files Modified

1. `wifitex/gui/multi_cracker.py` - Auto-detect all wordlists
2. `wifitex/gui/wordlist_manager.py` - Scan wifitex/wordlists folder
3. `wifitex/tools/aircrack.py` - CLI auto-detection
4. `wifitex/tools/hashcat.py` - CLI auto-detection
5. `wifitex/wordlists/` - New wordlist folder
6. `wifitex/wordlists/README.md` - Documentation

## Testing

```bash
# Test wordlist detection
python3 -c "from wifitex.gui.multi_cracker import MultiWordlistCracker; m = MultiWordlistCracker(); print('Found', len(m.wordlist_manager.get_all_wordlists()), 'wordlists')"
```

This will show how many wordlists were auto-detected!

