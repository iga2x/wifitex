# KARMA Handshake Capture Fix

## Problem Identified

KARMA handshake capture was failing while WPA capture succeeded on the same network. After comparing both implementations, three critical issues were found:

### Issue 1: Missing Channel Specification
**Problem**: KARMA was creating Airodump without specifying the target channel.
```python
# OLD (KARMA):
with Airodump(interface=self.probe_interface,
             target_bssid=ap_bssid,
             ...) as airodump:
```

**WPA does it correctly**:
```python
with Airodump(channel=self.target.channel,
              target_bssid=self.target.bssid,
              ...) as airodump:
```

**Impact**: Without channel specification, Airodump may not tune to the correct frequency, leading to missed handshakes.

### Issue 2: Incorrect Deauth Implementation
**Problem**: KARMA used manual subprocess calls to aireplay-ng with custom deauth logic.
```python
# OLD (KARMA):
deauth_cmd = ['aireplay-ng', '-0', '8', '--ignore-negative-one', ...]
subprocess.run(deauth_cmd, ...)
```

**WPA uses the proper Aireplay wrapper**:
```python
Aireplay.deauth(target.bssid, client_mac=client, timeout=1)
```

**Impact**: The custom deauth implementation may not work correctly or may interfere with the attack.

### Issue 3: Weak Handshake Validation
**Problem**: KARMA used custom async validation with aircrack-ng and tshark.
```python
# OLD (KARMA):
cmd = ['aircrack-ng', '-J', '/tmp/test_handshake', capfile]
result = subprocess.run(cmd, ...)
```

**WPA uses the Handshake class**:
```python
handshake = Handshake(capfile=cap_file, bssid=bssid, essid=essid)
if handshake.has_handshake():
```

**Impact**: Custom validation may incorrectly reject valid handshakes or miss errors.

## Solution Applied

### 1. Add Channel Specification
```python
# Get channel from target or real_networks
ap_channel = None
if hasattr(self, 'target') and self.target and hasattr(self.target, 'channel'):
    ap_channel = self.target.channel
elif self.real_networks:
    for network in self.real_networks:
        if hasattr(network, 'bssid') and network.bssid == ap_bssid:
            if hasattr(network, 'channel'):
                ap_channel = network.channel
                break

# Use channel in Airodump
with Airodump(interface=self.probe_interface,
             target_bssid=ap_bssid,
             channel=ap_channel,  # FIXED
             ...) as airodump:
```

### 2. Use Aireplay.deauth Like WPA
```python
# Send deauth periodically (matching WPA timing)
if current_time - last_deauth_check >= deauth_timeout:
    last_deauth_check = current_time
    try:
        # Use Aireplay.deauth like WPA does
        Aireplay.deauth(target_bssid=ap_bssid, client_mac=client_mac, timeout=2)
    except Exception as e:
        if Configuration.verbose > 1:
            Color.pl('{!} {R}Error sending deauth: {O}%s{W}' % str(e))
```

### 3. Use Handshake Class for Validation
```python
# Use Handshake class for validation (same as WPA)
from ..model.handshake import Handshake
handshake = Handshake(capfile=cap_file, bssid=ap_bssid)
if handshake.has_handshake():
    self.captured_handshakes[client_mac] = cap_file
    # Success!
```

### 4. Match WPA Timing and Behavior
- Use same timeout configuration (`wpa_attack_timeout`, `wpa_deauth_timeout`)
- Check for handshake every 2 seconds (matching WPA)
- Sleep 1 second between checks (matching WPA)
- Remove unnecessary adaptive timing

## Expected Results

After this fix, KARMA handshake capture should:
1. ✅ Successfully capture handshakes with the same reliability as WPA
2. ✅ Use proper channel tuning for better packet capture
3. ✅ Use proven deauth implementation
4. ✅ Validate handshakes correctly using the same logic as WPA
5. ✅ Respect user configuration timeouts

## Testing Recommendations

1. Run KARMA attack on a network where WPA handshake capture succeeds
2. Verify that handshakes are captured reliably
3. Check that captured handshakes can be cracked successfully
4. Compare success rate with WPA attack on the same network
