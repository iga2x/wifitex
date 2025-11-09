# Brute Force Attack Feature

Wifitex now supports **full brute force attacks** on captured WPA/WPA2/WPA3 handshakes and PMKID hashes.

## Overview

Brute force attacks try all possible password combinations using mask patterns, unlike dictionary attacks which only try passwords from wordlists.

### Attack Modes

Wifitex supports multiple hashcat attack modes:

- **Mode 0** (Dictionary): Try passwords from a wordlist
- **Mode 3** (Brute Force): Try all combinations using a mask pattern
- **Mode 6** (Hybrid Wordlist + Mask): Append mask to each word from wordlist
- **Mode 7** (Hybrid Mask + Wordlist): Prepend mask to each word from wordlist

## Configuration Options

Add these to your configuration or set via code:

```python
Configuration.use_brute_force = True          # Enable brute force
Configuration.brute_force_mode = '3'          # Attack mode: '3', '6', '7', or comma-separated like '3,6,7'
Configuration.brute_force_mask = '?a?a?a?a?a?a?a?a'  # Mask pattern
Configuration.brute_force_min_length = 8     # Min password length
Configuration.brute_force_max_length = 12     # Max password length
Configuration.brute_force_timeout = 3600     # Max time per attempt (seconds)
```

## Mask Patterns

Hashcat uses mask patterns to define character sets:

- `?l` = lowercase letters (a-z)
- `?u` = uppercase letters (A-Z)
- `?d` = digits (0-9)
- `?s` = special chars (!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)
- `?a` = all printable ASCII (letters, digits, special)
- `?b` = all bytes (0x00-0xff)

### Mask Examples

```python
# Try 8 character passwords with lowercase + digits
mask = '?l?l?l?l?l?l?l?l'  # Only lowercase: aaaa to zzzzzzzz

# Try 10 character passwords with all ASCII characters
mask = '?a?a?a?a?a?a?a?a?a?a'

# Try 8 character passwords with uppercase + digits
mask = '?u?u?d?d?u?u?d?d'  # Pattern: UPPERDIGITUPPERDIGIT...

# Try 6 character passwords with digits only
mask = '?d?d?d?d?d?d'
```

## Usage Examples

### Example 1: Pure Brute Force

Try all 8-character lowercase + digit combinations:

```python
from wifitex.config import Configuration
Configuration.use_brute_force = True
Configuration.brute_force_mode = '3'
Configuration.brute_force_mask = '?l?l?l?l?l?l?l?l'
```

### Example 2: Hybrid Attack (Wordlist + Mask)

Try each word from wordlist with common suffixes:

```python
Configuration.use_brute_force = True
Configuration.brute_force_mode = '6'
Configuration.brute_force_mask = '?d?d?d'  # Append 3 digits
Configuration.wordlist = '/path/to/wordlist.txt'
```

This tries: `password001`, `password002`, `password003`, etc.

### Example 3: Multiple Attack Modes

Try brute force first, then fall back to dictionary:

```python
Configuration.use_brute_force = True
Configuration.brute_force_mode = '3,0'  # Try brute force, then dictionary
Configuration.brute_force_mask = '?a?a?a?a?a?a?a?a'
Configuration.wordlist = '/path/to/wordlist.txt'
```

### Example 4: Specific Pattern

Target passwords with known patterns:

```python
# Assume password is like: "Password123!"
Configuration.brute_force_mask = '?u?l?l?l?l?l?l?l?d?d?d?s'
# First char uppercase, 7 lowercase, 3 digits, 1 special
```

## Performance Considerations

⚠️ **Warning**: Brute force attacks can take a VERY long time.

For an 8-character password with all ASCII characters (`?a?a?a?a?a?a?a?a`):
- **Total combinations**: 95^8 = 6,634,204,312,890,625 (6.6 quadrillion)
- **Time to crack** (with GPU at 10 billion H/s): ~7.5 days

### Recommended Strategies

1. **Use incremental lengths**: Start with shorter masks
2. **Use targeted charsets**: If you know the password structure (e.g., only letters)
3. **Use hybrid modes**: Combine wordlists with short masks
4. **Set timeouts**: Don't let attacks run indefinitely

### Example: Incremental Attack

```python
# Try 8-12 character passwords incrementally
for length in range(8, 13):
    mask = '?a' * length
    Configuration.brute_force_mask = mask
    # Run attack with timeout
```

## Command Line Usage (Future Enhancement)

While the GUI and Python API support brute force, command line support can be added:

```bash
# Hypothetical future CLI option
wifitex --brute-force --mask "?a?a?a?a?a?a?a?a" --mode 3 -i wlan0mon
```

## When to Use Brute Force

✅ **Use brute force when:**
- Dictionary attacks failed
- Password structure is known
- Short passwords (6-10 characters)
- Targeted password patterns

❌ **Avoid brute force when:**
- Long passwords (>12 characters)
- Unknown password structure
- All ASCII characters needed
- Limited time/resources

## Best Practices

1. **Start with dictionary attacks** - Much faster if password is common
2. **Use hybrid modes** - Combine wordlists with short masks
3. **Target likely patterns** - Passwords often follow patterns
4. **Set reasonable timeouts** - Don't wait forever
5. **Use GPU acceleration** - Much faster than CPU
6. **Capture PMKID when possible** - Faster than handshake capture

## GPU Acceleration

Hashcat automatically uses GPU if available. Check GPU support:

```bash
hashcat -I  # List available devices
hashcat --benchmark  # Test performance
```

GPU is typically 10-100x faster than CPU for brute force attacks.

## Example: Complete Brute Force Workflow

```python
# 1. Configure for brute force
from wifitex.config import Configuration

Configuration.use_brute_force = True
Configuration.brute_force_mode = '3,0'  # Try brute force, fall back to dict
Configuration.brute_force_mask = '?l?l?l?l?l?l?l?l'  # 8 lowercase chars
Configuration.brute_force_timeout = 7200  # 2 hour max
Configuration.wordlist = '/path/to/rockyou.txt'  # Fallback

# 2. Run attack (handshake will be captured and cracked)
# This automatically uses brute force when enabled
from wifitex.attack.wpa import AttackWPA
from wifitex.model.target import Target

target = Target(bssid='AA:BB:CC:DD:EE:FF', ...)
attack = AttackWPA(target)
result = attack.run()  # Will use brute force mode
```

## Advanced: Custom Mask Generation

```python
from wifitex.tools.hashcat import Hashcat

# Generate masks for different scenarios
length_10_all = Hashcat.generate_mask_from_length(10, '?a')
length_8_lower = Hashcat.generate_mask_from_length(8, '?l')
length_6_digits = Hashcat.generate_mask_from_length(6, '?d')

# Output:
# 10 char all: ?a?a?a?a?a?a?a?a?a?a
# 8 char lowercase: ?l?l?l?l?l?l?l?l
# 6 char digits: ?d?d?d?d?d?d
```

## Troubleshooting

### "Password too long"
- Reduce mask length or use targeted charset

### "Takes too long"
- Use shorter masks
- Use targeted character sets
- Try hybrid modes with wordlists
- Consider GPU acceleration

### "No GPU found"
- Install GPU drivers
- Use `--force` flag if software compatibility issues
- Check `hashcat -I` for device list

## Summary

Wifitex now supports full brute force attacks with multiple modes:
- ✅ Pure brute force (mode 3)
- ✅ Hybrid wordlist + mask (mode 6)  
- ✅ Hybrid mask + wordlist (mode 7)
- ✅ Multiple attack modes in sequence
- ✅ Configurable mask patterns
- ✅ GPU acceleration support
- ✅ Works with WPA/WPA2/WPA3 handshakes and PMKID

**Remember**: Brute force is powerful but slow. Always try dictionary attacks first!

