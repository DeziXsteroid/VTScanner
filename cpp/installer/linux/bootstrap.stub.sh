#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Network Tools 1.0.8"
APP_VERSION="__APP_VERSION__"
SELF_PATH="$0"
WORK_DIR="$(mktemp -d)"
PAYLOAD_DIR=""
LANG_CODE="ru"
INSTALL_DIR_DEFAULT="$HOME/.local/opt/Network-Tools-1.0.8"
INSTALL_DIR="$INSTALL_DIR_DEFAULT"
CREATE_SHORTCUT="yes"
INSTALL_DEPS="yes"

cleanup() {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

text() {
  local key="$1"
  case "$LANG_CODE:$key" in
    ru:choose_language) printf '%s' 'Выберите язык установщика:' ;;
    en:choose_language) printf '%s' 'Choose installer language:' ;;
    ru:choose_install_dir) printf '%s' 'Выберите папку установки приложения:' ;;
    en:choose_install_dir) printf '%s' 'Choose the application destination folder:' ;;
    ru:create_shortcut) printf '%s' 'Создать ярлык на рабочем столе?' ;;
    en:create_shortcut) printf '%s' 'Create a desktop shortcut?' ;;
    ru:install_dependencies) printf '%s' 'Установить системные зависимости для сборки и установки?' ;;
    en:install_dependencies) printf '%s' 'Install system dependencies required to build and install the application?' ;;
    ru:building) printf '%s' 'Сборка приложения...' ;;
    en:building) printf '%s' 'Building the application...' ;;
    ru:installing) printf '%s' 'Установка приложения...' ;;
    en:installing) printf '%s' 'Installing the application...' ;;
    ru:finished) printf '%s' 'Установка завершена.' ;;
    en:finished) printf '%s' 'Installation completed.' ;;
    ru:cancelled) printf '%s' 'Установка отменена.' ;;
    en:cancelled) printf '%s' 'Installation cancelled.' ;;
    ru:unsupported_pm) printf '%s' 'Не удалось определить пакетный менеджер Linux. Установите Qt6 и CMake вручную.' ;;
    en:unsupported_pm) printf '%s' 'Could not detect a supported Linux package manager. Install Qt6 and CMake manually.' ;;
    ru:launch_now) printf '%s' 'Запустить приложение сейчас?' ;;
    en:launch_now) printf '%s' 'Launch the application now?' ;;
    ru:desktop_name) printf '%s' 'Network Tools 1.0.8' ;;
    en:desktop_name) printf '%s' 'Network Tools 1.0.8' ;;
    *) printf '%s' "$key" ;;
  esac
}

abort_install() {
  printf '%s\n' "$(text cancelled)"
  exit 1
}

choose_language() {
  if command -v zenity >/dev/null 2>&1; then
    local choice
    choice="$(zenity --list --radiolist --title="Network Tools 1.0.8" --text="$(text choose_language)" --column="" --column="Language" TRUE "Русский" FALSE "English" --height=220 --width=360)" || abort_install
    if [[ "$choice" == "English" ]]; then
      LANG_CODE="en"
    else
      LANG_CODE="ru"
    fi
    return
  fi
  printf '%s\n1) Русский\n2) English\n' "$(text choose_language)"
  read -r choice
  if [[ "$choice" == "2" ]]; then
    LANG_CODE="en"
  else
    LANG_CODE="ru"
  fi
}

choose_install_dir() {
  if command -v zenity >/dev/null 2>&1; then
    local choice
    choice="$(zenity --file-selection --directory --title="Network Tools 1.0.8" --filename="$INSTALL_DIR_DEFAULT/" 2>/dev/null)" || abort_install
    INSTALL_DIR="$choice"
    return
  fi
  printf '%s [%s]: ' "$(text choose_install_dir)" "$INSTALL_DIR_DEFAULT"
  read -r choice
  if [[ -n "${choice:-}" ]]; then
    INSTALL_DIR="$choice"
  fi
}

ask_yes_no() {
  local prompt_key="$1"
  local default_value="$2"
  if command -v zenity >/dev/null 2>&1; then
    if zenity --question --title="Network Tools 1.0.8" --text="$(text "$prompt_key")"; then
      printf '%s' yes
    else
      printf '%s' no
    fi
    return
  fi
  if [[ "$default_value" == "yes" ]]; then
    printf '%s [Y/n]: ' "$(text "$prompt_key")"
  else
    printf '%s [y/N]: ' "$(text "$prompt_key")"
  fi
  read -r reply
  if [[ -z "${reply:-}" ]]; then
    printf '%s' "$default_value"
    return
  fi
  case "$reply" in
    y|Y|yes|YES|д|Д|да|ДА) printf '%s' yes ;;
    *) printf '%s' no ;;
  esac
}

extract_payload() {
  local archive_line
  archive_line="$(awk '/^__ARCHIVE_BELOW__$/{print NR + 1; exit 0; }' "$SELF_PATH")"
  if [[ -z "$archive_line" ]]; then
    echo "Installer payload is missing." >&2
    exit 1
  fi
  mkdir -p "$WORK_DIR"
  tail -n +"$archive_line" "$SELF_PATH" | tar -xz -C "$WORK_DIR"
  PAYLOAD_DIR="$WORK_DIR/payload"
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    printf '%s' apt
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    printf '%s' dnf
    return
  fi
  if command -v pacman >/dev/null 2>&1; then
    printf '%s' pacman
    return
  fi
  if command -v zypper >/dev/null 2>&1; then
    printf '%s' zypper
    return
  fi
  printf '%s' unknown
}

install_dependencies() {
  local pm
  pm="$(detect_package_manager)"
  case "$pm" in
    apt)
      sudo apt-get update
      sudo apt-get install -y build-essential cmake qt6-base-dev qt6-serialport-dev rsync curl
      ;;
    dnf)
      sudo dnf install -y gcc-c++ make cmake qt6-qtbase-devel qt6-qtserialport-devel rsync curl
      ;;
    pacman)
      sudo pacman -Sy --needed base-devel cmake qt6-base qt6-serialport rsync curl
      ;;
    zypper)
      sudo zypper install -y gcc-c++ make cmake libqt6-qtbase-devel libqt6-qtserialport-devel rsync curl
      ;;
    *)
      printf '%s\n' "$(text unsupported_pm)"
      exit 1
      ;;
  esac
}

run_install() {
  if [[ -w "$INSTALL_DIR" || ( ! -e "$INSTALL_DIR" && -w "$(dirname "$INSTALL_DIR")" ) ]]; then
    cmake --install "$WORK_DIR/build"
  else
    sudo cmake --install "$WORK_DIR/build"
  fi
}

create_desktop_entry() {
  local desktop_dir="$HOME/.local/share/applications"
  local desktop_file="$desktop_dir/network-tools-1.0.desktop"
  mkdir -p "$desktop_dir"
  cat > "$desktop_file" <<EOF
[Desktop Entry]
Type=Application
Name=$(text desktop_name)
Exec=$INSTALL_DIR/bin/NetworkToolsQt
Icon=$INSTALL_DIR/share/icons/hicolor/1024x1024/apps/NetworkToolsQt.png
Terminal=false
Categories=Network;Utility;
EOF
  chmod +x "$desktop_file"
  if [[ "$CREATE_SHORTCUT" == "yes" && -d "$HOME/Desktop" ]]; then
    cp "$desktop_file" "$HOME/Desktop/Network Tools 1.0.desktop"
    chmod +x "$HOME/Desktop/Network Tools 1.0.desktop"
  fi
}

seed_manuf() {
  mkdir -p "$HOME/.local/share/NetWorkTools/data"
  cp -f "$PAYLOAD_DIR/manuf" "$HOME/.local/share/NetWorkTools/data/manuf"
}

build_and_install() {
  printf '%s\n' "$(text building)"
  cmake -S "$PAYLOAD_DIR/cpp" -B "$WORK_DIR/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"
  cmake --build "$WORK_DIR/build" --config Release -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
  printf '%s\n' "$(text installing)"
  run_install
  seed_manuf
  create_desktop_entry
}

launch_app() {
  if [[ -x "$INSTALL_DIR/bin/NetworkToolsQt" ]]; then
    "$INSTALL_DIR/bin/NetworkToolsQt" >/dev/null 2>&1 &
  fi
}

main() {
  choose_language
  choose_install_dir
  CREATE_SHORTCUT="$(ask_yes_no create_shortcut yes)"
  INSTALL_DEPS="$(ask_yes_no install_dependencies yes)"
  extract_payload
  if [[ "$INSTALL_DEPS" == "yes" ]]; then
    install_dependencies
  fi
  build_and_install
  printf '%s\n' "$(text finished)"
  if [[ "$(ask_yes_no launch_now yes)" == "yes" ]]; then
    launch_app
  fi
}

main "$@"
exit 0
__ARCHIVE_BELOW__
