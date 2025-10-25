# Install Script Fix - User Instructions

## Problem
GUI is missing the "Client Monitoring" tab after installation from GitHub.

## Root Cause
The install script was using editable mode (`-e`) which loads from source directory, not from installed package.

## Solution
The install.sh script has been fixed on GitHub. You need to:

1. **Uninstall old version**:
```bash
sudo python3 -m pip uninstall -y wifitex wifite
sudo rm -rf /usr/local/lib/python*/dist-packages/wifite*.egg
sudo rm -rf /usr/lib/python*/dist-packages/wifite
```

2. **Clone fresh from GitHub**:
```bash
cd /tmp
rm -rf wifitex_test
git clone https://github.com/iga2x/wifitex.git
cd wifitex
```

3. **Install with fixed script**:
```bash
sudo ./install.sh
```

## Verification
After installation, verify the fix:
```bash
python3 -c "
import sys
sys.path.remove('/home/your/current/dir')  # Remove dev dir from path
import wifitex.gui.main_window
print('✅ Client Monitoring:', hasattr(wifitex.gui.main_window.WifitexMainWindow, 'create_client_monitoring_tab'))
"
```

## For Current Situation
You are running from development directory which works fine. The issue only affects users who install from GitHub. The fix is now on GitHub and ready for them.
