#!/bin/bash
# Build script for DRT Encryptor
# Uses PyInstaller to bundle the script and pkgbuild to create an installer.

echo "Starting build process..."

# Clean previous
echo "Cleaning up..."
rm -rf build dist drtencrypt.spec drtencrypt.pkg

# Build binary
echo "Building binary with PyInstaller..."
# --onefile: bundle everything into one executable
# --name drtencrypt: name of the output binary
pyinstaller --onefile --name drtencrypt drt_encryptor.py

if [ ! -f "dist/drtencrypt" ]; then
    echo "PyInstaller failed! No binary found."
    exit 1
fi

echo "Binary built successfully at dist/drtencrypt"

# Prepare for package
echo "Preparing package payload..."
mkdir -p dist/payload/usr/local/bin
cp dist/drtencrypt dist/payload/usr/local/bin/

# Build package
echo "Building macOS package..."
pkgbuild --root dist/payload \
         --identifier com.dom.drtencrypt \
         --version 1.0 \
         --install-location / \
         drtencrypt.pkg

if [ -f "drtencrypt.pkg" ]; then
    echo "SUCCESS: drtencrypt.pkg created!"
    echo "Location: $(pwd)/drtencrypt.pkg"
else
    echo "pkgbuild failed!"
    exit 1
fi
