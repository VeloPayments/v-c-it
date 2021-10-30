#!/bin/sh

#get command-line arguments
args=$(getopt c $*)
if [ $? -ne 0 ]; then
    echo "Usage: run_integration_tests.sh [-c]"
    echo ""
    echo "where:"
    echo "\t-c      Continue; don't delete build or build from scratch."
    echo ""
    echo ""
    exit 1
fi

#by default, don't continue
cont=0

#parse command-line arguments
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

#verify that the script is running as root
if [ ! $(id -u) -eq 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

#verify that the integration_tests directory exists.
if [ ! -d /opt/integration_tests ]; then
    echo "Missing /opt/integration_tests"
    exit 1
fi

#verify that the veloagent user exists
veloagent_uid=$(id -u veloagent)
if [ $? -ne 0 ]; then
    echo "Missing veloagent user."
    exit 1
fi

#verify that the veloagent group exists
veloagent_gid=$(id -u veloagent)
if [ $? -ne 0 ]; then
    echo "Missing veloagent group."
    exit 1
fi

#get the unprivileged user
unprivileged_user=$SUDO_USER
if [ $(id -u $unprivileged_user) -eq 0 ]; then
    echo "Can't determine unpriviledged user."
    exit 1
else
    echo "Set unprivileged user to $unprivileged_user."
fi

#clean the build directory
if [ $cont -ne 1 ]; then
    if [ -d build ]; then
        echo "Cleaning up build directory."
        rm -rf build
    fi
fi

#output the package config path, possibly needed for minunit
echo "PKG_CONFIG_PATH = $PKG_CONFIG_PATH"

#for now on, exit on error
set -e

#if we are building from scratch, clean the build directory and reset
#subprojects
if [ $cont -ne 1 ]; then
    sudo -E -u $unprivileged_user mkdir build
    sudo -E -u $unprivileged_user meson subprojects update --reset
fi

#work from the build directory
cd build

#if we are building from scratch, run a full meson configure
if [ $cont -ne 1 ]; then
    sudo -E -u $unprivileged_user meson ..
#otherwise, do a reconfigure
else
    sudo -E -u $unprivileged_user meson --reconfigure ..
fi

#build all
sudo -E -u $unprivileged_user ninja

#run unit tests
sudo -E -u $unprivileged_user ninja test

#get the name of the agentd installation tarball
agentd_package=$(ls agentd*.tar.xz)
if [ ! -f $agentd_package ]; then
    echo "Error. Could not find agentd tarball."
    exit 1
else
    echo "Using agentd tarball $agentd_package"
fi

#get the name of the vctool binary
vctool_binary=$(ls subprojects/vctool/vctool)
if [ ! -f $vctool_binary ]; then
    echo "Error. Could not find vctool binary."
    exit 1
else
    echo "Using vctool binary $vctool_binary"
fi

#create a staging environment for the binaries.
rm -rf /opt/integration_tests/staging
mkdir /opt/integration_tests/staging

#stage the agentd tarball
cp $agentd_package /opt/integration_tests/staging
agentd_package=/opt/integration_tests/staging/$(basename $agentd_package)
echo "agentd tarball staged to $agentd_package"

#stage the vctool binary
cp $vctool_binary /opt/integration_tests/staging
vctool_binary=/opt/integration_tests/staging/$(basename $vctool_binary)
echo "vctool binary staged to $vctool_binary"
