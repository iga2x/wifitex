# Brute Force Mask Patterns for Wifitex

## Overview

Brute force attacks try ALL possible password combinations using mask patterns. This is MUCH slower than dictionary attacks but more comprehensive.

**For Wireless Passwords:**
- Minimum: 8 characters (WPA requirement)
- Maximum: 64 characters (WPA maximum)
- **Recommended target: 8-20 characters**

## Hashcat Mask Syntax

| Pattern | Meaning | Character Set | Count |
|---------|---------|---------------|-------|
| `?l` | Lowercase | a-z | 26 |
| `?u` | Uppercase | A-Z | 26 |
| `?d` | Digits | 0-9 | 10 |
| `?s` | Special | !@#$%^&*... | 32 |
| `?a` | All ASCII | All of above | 94 |

## Pre-defined Masks in GUI

Based on your password samples, here are optimized masks:

### 1. **Digits Only** (Fastest)
```
8 Digits: ?d?d?d?d?d?d?d?d
6 Digits: ?d?d?d?d?d?d
10 Digits: ?d?d?d?d?d?d?d?d?d?d
```
**Example passwords:**
- `2377132050356` (13 digits)
- `12345678` (8 digits)
- `1234567890123456` (16 digits)

**Estimated time (GPU):**
- 8 digits: ~17 seconds
- 10 digits: ~3 minutes
- 13 digits: ~2 hours

### 2. **Mixed Case + Special** (Your examples)
```
DarkWorld@isekai    → ?u?l?l?l?l?l?l?l?s?l?l?l?l?l?l
Darkworld@Isekai    → ?u?l?l?l?l?l?l?l?s?u?l?l?l?l?l
bR3#uiG$hV          → ?l?u?d?s?l?l?s?u?s?l?u
```

**Recommended masks:**
```python
# Mixed Case + Special (@, etc.)
"8 chars": ?u?l?l?l?l?l?l?l
"With Special": ?u?l?l?l?l?l?l?s
"Mixed All": ?u?l?l?l?l?l?d?s
"First Upper": ?u?l?l?l?l?l?l?l
```

### 3. **GUI Mask Patterns**

The GUI now includes these pre-defined patterns:

```python
"8 Digits Only (Fast)" → ?d?d?d?d?d?d?d?d
"6 Digits Only (Very Fast)" → ?d?d?d?d?d?d
"10 Digits (Phone/ID)" → ?d?d?d?d?d?d?d?d?d?d
"8 Lowercase (Common)" → ?l?l?l?l?l?l?l?l
"8 Uppercase" → ?u?u?u?u?u?u?u?u
"8 Mixed Case" → ?u?l?l?l?l?l?l?l
"8 Mixed Case+Digits" → ?u?l?l?l?l?l?d
"8 Lowercase+Digits" → ?l?l?l?l?l?l?d?d
"Mixed Case+Digits+Special" → ?u?l?l?l?l?l?d?s
"All ASCII (Slow)" → ?a?a?a?a?a?a?a?a
"Custom Pattern" → User-defined
```

## GPU Acceleration

**GPU is REQUIRED for practical brute force!**

### Without GPU (CPU only):
- 8 digits: ~50 minutes
- 8 lowercase: ~2 days
- 8 all ASCII: YEARS

### With GPU (Recommended):
- 8 digits: ~17 seconds
- 8 lowercase: ~6 hours
- 8 all ASCII: ~7 days

## Recommended Settings

### Fast Attack (8-12 chars)
```python
Min Length: 8
Max Length: 12
Mask: ?d?d?d?d?d?d?d?d  # Start with digits
Timeout: 60 minutes
```

### Common Patterns (8-16 chars)
```python
Min Length: 8
Max Length: 16
Mask: ?u?l?l?l?l?l?l?l  # First uppercase, then lowercase
Timeout: 2 hours
```

### Complex Passwords (8-20 chars)
```python
Min Length: 8
Max Length: 20
Mask: ?u?l?l?l?l?l?d?s  # Mixed case + digit + special
Timeout: 6 hours
```

## Performance Estimates

| Mask Pattern | Length | Combinations | GPU Time | CPU Time |
|--------------|--------|--------------|----------|----------|
| 6 digits | 6 | 1 million | ~10 sec | ~5 min |
| 8 digits | 8 | 100 million | ~17 sec | ~50 min |
| 10 digits | 10 | 10 billion | ~3 min | ~3 hours |
| 8 lowercase | 8 | 208 billion | ~6 hours | ~2 days |
| 8 mixed case | 8 | 52+ billion | ~1.5 hours | ~12 hours |
| 8 all ASCII | 8 | 6.6 quadrillion | ~7 days | Years |

## CLI Usage

```bash
# Enable brute force with custom mask
sudo wifitex --brute-force --brute-mask "?d?d?d?d?d?d?d?d"

# 8 character mixed case + digits
sudo wifitex --brute-force --brute-mask "?u?l?l?l?l?l?d?d"

# With timeout (1 hour)
sudo wifitex --brute-force --brute-mask "?a?a?a?a?a?a?a?a" --brute-timeout 3600
```

## GUI Usage

1. Go to **Settings Panel**
2. Enable **"Brute Force Attack (GPU-Accelerated)"**
3. Select mask pattern from dropdown
4. Set Min/Max length (8-20 recommended)
5. Set timeout (60 minutes default)
6. GPU status shown at bottom

## Pattern Examples

### Your Password Samples

```python
# Sample 1: 2377132050356 (13 digits)
Mask: ?d?d?d?d?d?d?d?d?d?d?d?d?d
Time: ~4 hours (GPU)

# Sample 2: DarkWorld@isekai
Mask: ?u?l?l?l?l?l?l?s?l?l?l?l?l
Time: ~2 days (GPU) - Very slow!

# Sample 3: bR3#uiG$hV
Mask: ?l?u?d?s?l?l?s?u?s?l?u
Time: ~3 hours (GPU)
```

## Best Practices

1. **Try dictionary first** - Always start with wordlist
2. **Use GPU** - Without GPU, brute force is impractical
3. **Start short** - 6-8 chars before 9+
4. **Know your target** - If you know it's digits, use `?d` not `?a`
5. **Set timeouts** - Don't run indefinitely
6. **Use hybrid modes** - Combine wordlists with masks

## Hybrid Mode Examples

### Mode 6: Wordlist + Mask Suffix
```python
Wordlist: rockyou.txt
Mask: ?d?d?d?d
Result: password0000, password0001, ... password9999
```

### Mode 7: Mask Prefix + Wordlist
```python
Mask: 1234
Wordlist: rockyou.txt
Result: 1234password, 1234admin, etc.
```

## Time Estimates for Your Samples

Based on RTX 3060 GPU (not real GPU - estimate):

| Password | Mask | Estimated Time |
|----------|------|----------------|
| `2377132050356` | 13 digits | ~4 hours |
| `DarkWorld@isekai` | Mixed + special | ~2 days |
| `Darkworld@Isekai` | Mixed + special | ~2 days |
| `bR3#uiG$hV` | Complex mix | ~3 hours |

## Mask Pattern Quick Reference

```python
# Digits
?d?d?d?d?d?d             # 6 digits (very fast)
?d?d?d?d?d?d?d?d         # 8 digits (fast)
?d?d?d?d?d?d?d?d?d?d     # 10 digits (medium)

# Lowercase
?l?l?l?l?l?l?l?l         # 8 lowercase (medium)
?l?l?l?l?l?l             # 6 lowercase (fast)

# Mixed Case
?u?l?l?l?l?l?l?l         # 8 chars, first upper (medium)
?u?u?l?l?l?l?l?l         # 8 chars, 2 upper (medium)
?u?l?d?s?l?l?l?l         # Complex mix (slow)

# All ASCII (SLOW!)
?a?a?a?a?a?a?a?a         # 8 all ASCII (very slow)
```

## ⚠️ Warnings

1. **GPU Required** - CPU-only brute force is impractical
2. **Set Timeouts** - Can run indefinitely
3. **Start Short** - 6-8 chars before longer
4. **Use Targeted Masks** - Don't use `?a` unless necessary
5. **Try Dictionary First** - Much faster

## Summary

Your GUI now has:
- ✅ Pre-defined mask patterns for common passwords
- ✅ Custom mask input for advanced users
- ✅ Min/Max length controls (8-64)
- ✅ Timeout settings (1 min - 24 hours)
- ✅ GPU detection and status
- ✅ Attack mode selection (pure brute, hybrid)
- ✅ Auto-detects if GPU is available

**Always try dictionary attacks first, brute force as last resort!**

