# How to Use the Updated GUI with Client Monitoring

## Problem
The GUI you're running was installed before the client monitoring feature was added.

## Solutions

### Option 1: Run from Development Directory (Recommended)
Run the GUI directly from the source code:

```bash
cd /home/iganomono/Downloads/wifiteX-master
python3 -m wifitex.gui
```

### Option 2: Use the Launch Script
Run the provided script:

```bash
chmod +x /tmp/test_gui.sh
/tmp/test_gui.sh
```

### Option 3: Reinstall the Package (Requires sudo)
If you need to install system-wide:

```bash
cd /home/iganomono/Downloads/wifiteX-master
sudo python3 setup.py install --force
```

Or using pip with override:

```bash
cd /home/iganomono/Downloads/wifiteX-master
pip3 install -e . --break-system-packages
```

### Option 4: Run with PYTHONPATH
Set the Python path to use the development version:

```bash
export PYTHONPATH=/home/iganomono/Downloads/wifiteX-master:$PYTHONPATH
python3 -m wifitex.gui
```

## Verify Installation

Check if the new features are available:

```bash
cd /home/iganomono/Downloads/wifiteX-master
python3 -c "
from wifitex.gui.main_window import WifitexMainWindow
from wifitex.attack.karma import AttackKARMA

print('✅ Client Monitoring:', hasattr(WifitexMainWindow, 'create_client_monitoring_tab'))
print('✅ KARMA Monitoring:', hasattr(WifitexMainWindow, 'update_karma_client_monitoring'))
print('✅ Status API:', hasattr(AttackKARMA, 'get_karma_status'))
"
```

Should output:
```
✅ Client Monitoring: True
✅ KARMA Monitoring: True
✅ Status API: True
```

## What's New in the GUI

1. **Client Monitoring Tab**: New tab in the GUI showing connected clients
2. **Real-time Updates**: Refreshes every 5 seconds during KARMA attacks
3. **Traffic Statistics**: Shows handshakes, passwords, credentials
4. **PCAP Access**: Fixed folder access buttons
5. **No Freezing**: Optimized to prevent GUI freezing

## Troubleshooting

### GUI Still Shows Old Interface
- Make sure you're running from the source directory
- Check PYTHONPATH is set correctly
- Restart the GUI completely

### Features Still Missing
- Verify the commit is correct: `git log --oneline -1`
- Should show: "Add KARMA attack GUI client monitoring..."

### Can't Find Client Monitoring Tab
- Look for a tab named "Client Monitoring" in the right panel
- It's between "Attack Info" and "Settings" tabs
- Only shows during active KARMA attacks

## Quick Start

1. Open terminal
2. Run: `cd /home/iganomono/Downloads/wifiteX-master && python3 -m wifitex.gui`
3. Start a KARMA attack
4. Switch to "Client Monitoring" tab
5. Watch clients connect in real-time!

## Status

✅ All features are in the code
✅ Code is pushed to GitHub
✅ Ready to use from development directory
⚠️  Needs reinstall for system-wide access
