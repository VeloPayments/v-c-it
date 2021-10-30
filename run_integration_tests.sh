#!/bin/sh

args=$(getopt c $*)
if [ $? -ne 0 ]; then
    echo "Usage: run_integration_tests.sh [-c]"
    echo ""
    echo "where:"
    echo "\t-c      Continue; don't delete build and build from scratch."
    echo ""
    echo ""
    exit 1
fi

#by default, don't continue
cont=0

set -- $args
while [ $# -ne 0 ]
do
    case "$1"
    in
        -c)
            cont=1; shift;;
        --)
            shift; break;;
    esac
done

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

if [ $cont -ne 1 ]; then
    if [ -d build ]; then
        echo "Cleaning up build directory."
        rm -rf build
    fi
fi

echo "PKG_CONFIG_PATH = $PKG_CONFIG_PATH"

set -e

if [ $cont -ne 1 ]; then
    sudo -E -u $unprivileged_user mkdir build
    sudo -E -u $unprivileged_user meson subprojects update --reset
fi

cd build
if [ $cont -ne 1 ]; then
    sudo -E -u $unprivileged_user meson ..
else
    sudo -E -u $unprivileged_user meson --reconfigure ..
fi

sudo -E -u $unprivileged_user ninja
sudo -E -u $unprivileged_user ninja test
