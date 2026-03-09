#!/bin/bash

# install.sh - Update Response Checker + Tools Pendukung
# Dukungan: Linux (Ubuntu/Debian) dan Termux (Android)

set -e  # hentikan jika ada error

echo "========================================="
echo "  Installer Response Checker + Tools"
echo "========================================="

# Deteksi sistem operasi
if [ -n "$PREFIX" ] && [ -d "$PREFIX/lib" ]; then
    # Termux
    IS_TERMUX=true
    PKG_MGR="pkg"
    INSTALL_CMD="pkg install -y"
    PYTHON_PKG="python"
    PIP_CMD="pip"
else
    # Linux (Ubuntu/Debian)
    IS_TERMUX=false
    PKG_MGR="apt"
    INSTALL_CMD="sudo apt install -y"
    PYTHON_PKG="python3 python3-pip"
    PIP_CMD="pip3"
fi

# Fungsi instal Go di Linux (non-Termux)
install_go_linux() {
    echo "[*] Menginstal Go (Linux)..."
    wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
    rm go1.22.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> $HOME/.bashrc
}

# Update dan instal paket dasar
echo "[1] Memperbarui repositori dan menginstal paket dasar..."
if $IS_TERMUX; then
    $PKG_MGR update -y
    $INSTALL_CMD $PYTHON_PKG git
else
    sudo apt update
    $INSTALL_CMD $PYTHON_PKG git wget
fi

# Instal Go
echo "[2] Memasang Go..."
if $IS_TERMUX; then
    # Termux: go tersedia di pkg
    $INSTALL_CMD golang
else
    if ! command -v go &> /dev/null; then
        install_go_linux
    else
        echo "   Go sudah terinstal."
    fi
fi

# Pastikan $HOME/go/bin ada di PATH
export PATH=$PATH:$HOME/go/bin
if ! $IS_TERMUX; then
    # Tambahkan ke .bashrc jika belum ada
    if ! grep -q '$HOME/go/bin' $HOME/.bashrc; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> $HOME/.bashrc
    fi
fi

# Instal/update subfinder
echo "[3] Menginstal/memperbarui subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Instal/update bugscanner-go
echo "[4] Menginstal/memperbarui bugscanner-go..."
go install -v github.com/aztecrabbit/bugscanner-go@latest

# Update git pull
echo "[5] Memperbarui repository Scanner..."
if [ -d "Scanner" ]; then
    cd Scanner
    git pull
else
    echo "   Error: Direktori Scanner tidak ditemukan!"
    echo "   Pastikan Anda sudah menjalankan git clone terlebih dahulu."
    exit 1
fi

# Instal dependensi Python
echo "[6] Menginstal dependensi Python..."
$PIP_CMD install -r requirements.txt --break-system-packages 2>/dev/null || $PIP_CMD install -r requirements.txt

echo ""
echo "========================================="
echo "  Instalasi selesai!"
echo "  Pastikan untuk menjalankan: source ~/.bashrc"
echo "  (atau buka terminal baru)"
echo "========================================="
