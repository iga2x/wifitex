# Brute Force - CLI Usage Guide

## ✅ **CLI Support Added!**

Brute force is now available via command line (disabled by default).

## 🚀 **Quick Commands**

### Enable Brute Force

```bash
# Basic brute force (uses default 8 char all ASCII - VERY SLOW!)
sudo wifitex --brute-force

# Brute force with 6-digit PIN (FAST - recommended)
sudo wifitex --brute-force --brute-mask "?d?d?d?d?d?d"

# Brute force with 8 lowercase characters
sudo wifitex --brute-force --brute-mask "?l?l?l?l?l?l?l?l"

# With custom timeout (30 minutes)
sudo wifitex --brute-force --brute-mask "?d?d?d?d?d?d" --brute-timeout 1800
```

### Hybrid Modes

```bash
# Mode 6: Wordlist + mask (append digits to each word)
sudo wifitex --brute-force --brute-mode 6 --brute-mask "?d?d?d?d" --dict /path/to/wordlist.txt

# Mode 7: Mask + wordlist (prepend mask to each word)
sudo wifitex --brute-force --brute-mode 7 --brute-mask "1234" --dict /path/to/wordlist.txt
```

## 📋 **Available CLI Options**

| Option | Description | Example |
|--------|-------------|---------|
| `--brute-force` | Enable brute force mode | `--brute-force` |
| `--brute-mode [mode]` | Attack mode: 3=brute, 6=hybrid+wl, 7=hybrid+mask | `--brute-mode 3` |
| `--brute-mask [mask]` | Mask pattern | `--brute-mask "?d?d?d?d?d?d"` |
| `--brute-timeout [sec]` | Max time in seconds | `--brute-timeout 1800` |

## 🎯 **Mask Patterns**

| Pattern | Meaning | Example |
|---------|---------|---------|
| `?d` | Digits (0-9) | `?d?d?d?d` = 4 digits |
| `?l` | Lowercase (a-z) | `?l?l?l` = 3 lowercase |
| `?u` | Uppercase (A-Z) | `?u?u` = 2 uppercase |
| `?s` | Special chars | `?s?s` = 2 special |
| `?a` | All ASCII | `?a?a?a?a` = 4 any chars |

## ⚠️ **Important Notes**

1. **Disabled by default** - Won't run unless `--brute-force` is specified
2. **VERY slow** - Can take hours/days depending on mask
3. **Use targeted masks** - Don't use all ASCII for long passwords
4. **Start short** - Try 6-8 characters first
5. **Set timeouts** - Don't run indefinitely

## 💡 **Recommended Usage**

### Fast: 6-8 digit PINs
```bash
sudo wifitex --brute-force --brute-mask "?d?d?d?d?d?d" --brute-timeout 1800
```

### Medium: 6-8 lowercase
```bash
sudo wifitex --brute-force --brute-mask "?l?l?l?l?l?l?l?l" --brute-timeout 3600
```

### Slow: 6-8 all ASCII
```bash
sudo wifitex --brute-force --brute-mask "?a?a?a?a?a?a" --brute-timeout 7200
```

### Best: Hybrid (wordlist + digits)
```bash
sudo wifitex --brute-force --brute-mode 6 --brute-mask "?d?d?d?d" --dict /usr/share/wordlists/rockyou.txt
```

## 📊 **Performance Estimates**

| Mask | Length | Combinations | CPU Time | GPU Time |
|------|--------|--------------|----------|----------|
| `?d?d?d?d?d?d` | 6 digits | 1 million | ~5 min | ~10 sec |
| `?d?d?d?d?d?d?d?d` | 8 digits | 100 million | ~50 min | ~15 min |
| `?l?l?l?l?l?l?l?l` | 8 lowercase | 208 billion | ~2 days | ~7 hours |
| `?a?a?a?a?a?a?a?a` | 8 all ASCII | 6.6 quadrillion | Years | ~7 days |

## 🔍 **Help Output**

```bash
# See basic help
sudo wifitex -h

# See verbose help (shows all brute force options)
sudo wifitex -h -v | grep brute
```

## 📝 **Examples**

### Example 1: Crack 6-digit WiFi PIN
```bash
sudo wifitex -i wlan0mon --brute-force --brute-mask "?d?d?d?d?d?d" --brute-timeout 1800
```

### Example 2: Attack with 8 lowercase password
```bash
sudo wifitex --wpa --brute-force --brute-mask "?l?l?l?l?l?l?l?l" --brute-timeout 7200
```

### Example 3: Hybrid attack (wordlist + 4 digits)
```bash
sudo wifitex --brute-force --brute-mode 6 --brute-mask "?d?d?d?d" --dict /usr/share/wordlists/rockyou.txt
```

### Example 4: Multiple networks with brute force
```bash
sudo wifitex -i wlan0mon --brute-force --brute-mask "?d?d?d?d?d?d?d?d" --wpat 300
```

## ✅ **Status: Ready but Disabled by Default**

- ✅ Code added
- ✅ Help text working
- ✅ All options functional
- ⚠️  Disabled by default (must use `--brute-force` flag)
- ⚠️  Use responsibly - can take a VERY long time!

## 🎯 **Quick Start**

```bash
# 1. Scan and select target
sudo wifitex --wpa

# 2. Attack with brute force (6 digits)
sudo wifitex --brute-force --brute-mask "?d?d?d?d?d?d"

# 3. Wait for results or timeout
```

---

**Note**: Brute force is very slow. Always try dictionary attacks first!

