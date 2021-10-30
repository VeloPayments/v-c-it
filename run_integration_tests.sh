#!/bin/sh

if [ ! $(id -u) -eq 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

if [ ! -d /opt/integration_tests ]; then
    echo "Missing /opt/integration_tests"
    exit 1
fi

unprivileged_user=$SUDO_USER
if [ $(id -u $unprivileged_user) -eq 0 ]; then
    echo "Can't determine unpriviledged user."
    exit 1
else
    echo "Set unprivileged user to $unprivileged_user."
fi

if [ -d build ]; then
    echo "Cleaning up build directory."
    rm -rf build
fi

set -e

echo "PKG_CONFIG_PATH = $PKG_CONFIG_PATH"

sudo -E -u $unprivileged_user mkdir build
cd build
sudo -E -u $unprivileged_user meson ..
sudo -E -u $unprivileged_user ninja
sudo -E -u $unprivileged_user ninja test
