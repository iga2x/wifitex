#!/bin/bash
# Wifitex Uninstallation Script (improved - removes app directories too)
set -euo pipefail

echo "🗑️  Wifitex Uninstallation Script"
echo "================================="

# require root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Run as root: sudo $0"
  exit 1
fi

read -p "⚠️  This will remove Wifitex and system-wide components. Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# Helpers to detect dirs
detect_bin_dir() {
  for d in /usr/local/bin /usr/bin /opt/bin; do [ -d "$d" ] && { echo "$d"; return; }; done
  echo "/usr/local/bin"
}
detect_desktop_dir() {
  for d in /usr/share/applications /usr/local/share/applications /opt/share/applications; do [ -d "$d" ] && { echo "$d"; return; }; done
  echo "/usr/share/applications"
}
detect_icon_dir() {
  for d in /usr/share/pixmaps /usr/local/share/pixmaps /usr/share/icons /opt/share/pixmaps; do [ -d "$d" ] && { echo "$d"; return; }; done
  echo "/usr/share/pixmaps"
}
detect_data_dirs() {
  echo "/usr/share/wifitex /usr/local/share/wifitex /opt/wifitex /var/lib/wifitex"
}

BIN_DIR="$(detect_bin_dir)"
DESKTOP_APPS_DIR="$(detect_desktop_dir)"
ICON_DIR="$(detect_icon_dir)"
DATA_DIRS="$(detect_data_dirs)"

echo "Detected BIN_DIR: $BIN_DIR"
echo "Detected DESKTOP_APPS_DIR: $DESKTOP_APPS_DIR"
echo "Detected ICON_DIR: $ICON_DIR"

# 1) Try uninstalling python package
echo "📦 Uninstalling Wifitex Python package (if present)..."
if command -v pip3 &> /dev/null; then
  pip3 uninstall -y wifitex || true
fi
if command -v pip &> /dev/null; then
  pip uninstall -y wifitex || true
fi

# 2) Remove launchers & binaries
echo "🔧 Removing launchers and binaries..."
for name in wifitex wifitex-gui wifitex-gui-launcher wifitex-gui-real; do
  for dir in "$BIN_DIR" /usr/bin /opt/bin; do
    [ -e "$dir/$name" ] || continue
    chattr -i "$dir/$name" 2>/dev/null || true
    rm -f "$dir/$name" || true
    echo "✓ Removed $dir/$name"
  done
done

# 3) Remove desktop entries
echo "🖥️  Removing desktop entries..."
for df in "wifitex-gui.desktop" "wifitex.desktop"; do
  for ddir in "$DESKTOP_APPS_DIR" /usr/local/share/applications /opt/share/applications; do
    [ -f "$ddir/$df" ] || continue
    chattr -i "$ddir/$df" 2>/dev/null || true
    rm -f "$ddir/$df" || true
    echo "✓ Removed $ddir/$df"
  done
done

# 4) Remove user desktop shortcuts for sudo user
if [ -n "${SUDO_USER-}" ]; then
  USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  USER_DESKTOP="$USER_HOME/Desktop"
  for df in "wifitex-gui.desktop" "wifitex.desktop"; do
    [ -f "$USER_DESKTOP/$df" ] || continue
    chattr -i "$USER_DESKTOP/$df" 2>/dev/null || true
    rm -f "$USER_DESKTOP/$df" || true
    echo "✓ Removed user desktop shortcut: $USER_DESKTOP/$df"
  done
fi

# 5) Remove icons (cover current wifitex-* assets)
echo "🎨 Removing icons and full picture icon components..."
ICON_PATTERNS=( "wifitex-*.png" "wifitex.*" )

# Remove from pixmaps directory (full picture mode)
for dir in "$ICON_DIR" /usr/local/share/pixmaps /usr/share/icons /opt/share/pixmaps; do
  for pat in "${ICON_PATTERNS[@]}"; do
    shopt -s nullglob
    for f in "$dir"/$pat; do
      chattr -i "$f" 2>/dev/null || true
      rm -f "$f" || true
      echo "✓ Removed $f"
    done
    shopt -u nullglob
  done
done

# Remove PolicyKit icons
echo "🔐 Removing PolicyKit icons..."
for dir in /usr/share/icons/hicolor/48x48/apps /usr/share/icons/hicolor/256x256/apps; do
  [ -d "$dir" ] || continue
  for pat in "wifitex*"; do
    shopt -s nullglob
    for f in "$dir"/$pat; do
      chattr -i "$f" 2>/dev/null || true
      rm -f "$f" || true
      echo "✓ Removed PolicyKit icon $f"
    done
    shopt -u nullglob
  done
done

# Remove user icon cache and custom icons
if [ -n "${SUDO_USER-}" ]; then
  USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  USER_ICON_DIR="$USER_HOME/.local/share/icons"
  if [ -d "$USER_ICON_DIR" ]; then
    for pat in "${ICON_PATTERNS[@]}"; do
      shopt -s nullglob
      for f in "$USER_ICON_DIR"/$pat; do
        chattr -i "$f" 2>/dev/null || true
        rm -f "$f" || true
        echo "✓ Removed user icon $f"
      done
      shopt -u nullglob
    done
  fi
fi

# 6) Remove PolicyKit policy files
echo "🔐 Removing PolicyKit policy files..."
for pf in /usr/share/polkit-1/actions/wifitex*.policy; do
  [ -f "$pf" ] || continue
  chattr -i "$pf" 2>/dev/null || true
  rm -f "$pf" || true
  echo "✓ Removed PolicyKit policy: $pf"
done

# 7) Remove man pages and docs
echo "📚 Removing docs and man pages..."
for mf in /usr/share/man/man1/wifitex*.1 /usr/local/share/man/man1/wifitex*.1; do
  [ -f "$mf" ] || continue
  chattr -i "$mf" 2>/dev/null || true
  rm -f "$mf" || true
  echo "✓ Removed $mf"
done
for dd in /usr/share/doc/wifitex /usr/local/share/doc/wifitex; do
  [ -d "$dd" ] || continue
  chattr -R -i "$dd" 2>/dev/null || true
  rm -rf "$dd" || true
  echo "✓ Removed $dd"
done

# 8) Remove data/application directories
echo "📁 Removing application/data directories..."
for d in /usr/share/wifitex /usr/local/share/wifitex /opt/wifitex /var/lib/wifitex /usr/local/lib/wifitex; do
  [ -e "$d" ] || continue
  chattr -R -i "$d" 2>/dev/null || true
  rm -rf "$d" || true
  echo "✓ Removed $d"
done

# 9) Remove leftover site-packages / python files for wifitex
echo "🐍 Cleaning Python site-packages and caches..."
PY_PATHS=( "/usr/local/lib/python3*/dist-packages" "/usr/local/lib/python3*/site-packages" "/usr/lib/python3*/dist-packages" "/usr/lib/python3*/site-packages" )
for base in "${PY_PATHS[@]}"; do
  for resolved in $(echo $base); do
    shopt -s nullglob
    for pkg in "$resolved"/wifitex*; do
      chattr -R -i "$pkg" 2>/dev/null || true
      rm -rf "$pkg" || true
      echo "✓ Removed $pkg"
    done
    shopt -u nullglob
  done
done

# Remove leftover __pycache__ entries (best-effort, silence errors)
find / -path "*/wifitex/__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true

# 10) Clear user caches for immediate effect
if [ -n "${SUDO_USER-}" ]; then
  USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  echo "🧹 Clearing user caches..."
  
  # Clear icon caches
  rm -rf "$USER_HOME/.cache/icon-cache.kcache" 2>/dev/null || true
  rm -rf "$USER_HOME/.cache/thumbnails"/* 2>/dev/null || true
  rm -rf "$USER_HOME/.cache/gnome-applications" 2>/dev/null || true
  
  echo "✓ User caches cleared"
fi

# 11) Update desktop / icon caches
echo "🔄 Updating caches..."
if command -v update-desktop-database &> /dev/null; then
  update-desktop-database "$DESKTOP_APPS_DIR" 2>/dev/null || true
  echo "✓ Desktop database updated"
fi
if command -v gtk-update-icon-cache &> /dev/null; then
  gtk-update-icon-cache /usr/share/icons/hicolor/ -f 2>/dev/null || true
  echo "✓ Icon cache updated"
fi

echo ""
###############################################
# 12) Optional local project cleanup (repo dir)
###############################################

# Support non-interactive local purge via flag
PURGE_LOCAL="false"
for arg in "${@-}"; do
  if [ "$arg" = "--purge-local" ]; then
    PURGE_LOCAL="true"
  fi
done

# Detect if we're in a project checkout and optionally remove local build artifacts
if [ -f "setup.py" ] && [ -d "wifitex" ]; then
  if [ "$PURGE_LOCAL" = "true" ]; then
    DO_PURGE="y"
  else
    read -p "🧽 Also remove local build artifacts in this folder (build/, dist/, *.egg-info, __pycache__)? (y/N): " -n 1 -r
    echo
    DO_PURGE="$REPLY"
  fi

  if [[ $DO_PURGE =~ ^[Yy]$ ]]; then
    echo "🧹 Removing local build artifacts..."
    rm -rf build/ dist/ *.egg-info 2>/dev/null || true
    find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
    echo "✓ Local artifacts removed (build/, dist/, *.egg-info, __pycache__)"
  fi
fi

echo "🎉 Uninstallation completed successfully!"
echo "========================================="
echo "✅ All Wifitex components removed:"
echo "   • Python package and modules"
echo "   • Launcher scripts and binaries"
echo "   • Desktop entries and shortcuts"
echo "   • Icons (including full picture mode components)"
echo "   • PolicyKit policy files"
echo "   • Documentation and man pages"
echo "   • Application data directories"
echo "   • Python caches and site-packages"
echo "   • User caches and icon caches"
if [ -f "setup.py" ] && [ -d "wifitex" ]; then
  echo "   • Local repo artifacts (if selected)"
fi
echo ""
echo "💡 If you still see icons or menu entries, try logging out and back in."
echo "🔄 System caches have been refreshed for immediate effect."