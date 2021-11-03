#!/bin/sh

testdir=$INTEGRATION_TEST_DIR/$(basename $0 .sh)
agentd_dir=$testdir/$(basename $agentd_package .tar.xz)

set -e

#make sure no other agentd instance is running
agentd_count=$(ps -ef | grep agentd | grep -v grep | wc -l)
if [ $agentd_count -gt 0 ]; then
    echo "agentd is already running. Stop this service and restart tests."
    ps -ef | grep agentd | grep -v grep
    exit 1
fi

build_dir=$(pwd)

echo "Setting up $agentd_dir"
mkdir -p $testdir
cd $testdir
xz -dc $agentd_package | tar -xvf -
chown -R veloagent:veloagent $agentd_dir
chmod u+w,o+r $agentd_dir/etc/agentd.conf

#create a private key and public key for the handshake test
cd $testdir
$vctool_binary -N -o handshake.priv keygen
$vctool_binary -k handshake.priv -o handshake.pub pubkey

#create a private key for agentd
mkdir -p $agentd_dir/priv
cd $agentd_dir/priv
$vctool_binary -N -o agentd.priv keygen
$vctool_binary -k agentd.priv -o agentd.pub pubkey
chown veloagent:veloagent agentd.priv
cp agentd.pub $testdir

cd ..
echo "private key priv/agentd.priv" >> etc/agentd.conf

#verify that we can start agentd
cd $agentd_dir
bin/agentd start

echo "Sleeping to let agentd start."
sleep 2

echo "Verifying that agentd is running."

#make sure agentd has started
agentd_count=$(ps -ef | grep agentd | grep -v grep | wc -l)
if [ $agentd_count -gt 3 ]; then
    echo "agentd is running."
else
    echo "agentd couldn't be started. test fail."
    exit 1
fi

#change to the build directory
cd $testdir

#copy the handshake test binary here
cp $build_dir/src/test_handshake/test_handshake .

#disable error exit
set +e

#run the test
./test_handshake
handshake_result=$?

if [ $handshake_result -eq 102 ]; then
    echo "Unauthorized handshake denied as expected."
elif [ $handshake_result -eq 0 ]; then
    echo "ERROR: Unauthorized handshake should have failed."
    exit 1
else
    echo "Some other client connection error has occurred."
    exit 1
fi

#re-enable error exit
set -e

#get the agentd supervisor pid
agentd_supervisor_pid=$(ps -ef | grep agentd | grep -v grep | grep supervisor | awk '{ print $2 }')
if [ "$agentd_supervisor_pid" == "" ]; then
    echo "agentd supervisor is not running."
    exit 1
fi

#verify that it is a valid pid
if [ $agentd_supervisor_pid -le 1 ]; then
    echo "invalid agentd supervisor pid."
    exit 1
fi

#stop agentd
echo "Stopping agentd."
kill -TERM $agentd_supervisor_pid

echo "Sleeping to let agentd quiesce."
sleep 10

#make sure that agentd is stopped
agentd_count=$(ps -ef | grep agentd | grep -v grep | wc -l)
if [ $agentd_count -gt 0 ]; then
    echo "agentd couldn't be stopped."
    ps -ef | grep agentd | grep -v grep
    exit 1
fi

echo "agentd is stopped."
