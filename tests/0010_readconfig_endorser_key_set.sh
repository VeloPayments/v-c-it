#!/bin/sh

#don't use this as a template

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

#make sure that there is no TIME_WAIT shenanigans going on.
wait_loop=0
while [ $wait_loop -eq 0 ]; do
    time_wait=$(netstat -a | grep 4931 | grep TIME_WAIT | wc -l)
    if [ $time_wait -gt 0 ]; then
        echo "Waiting for TIME_WAIT on agentd port to end."
        sleep 10
    else
        wait_loop=1
    fi
done

build_dir=$(pwd)

echo "Setting up $agentd_dir"
mkdir -p $testdir
cd $testdir
xz -dc $agentd_package | tar -xvf -
chown -R veloagent:veloagent $agentd_dir
chmod u+w,o+r $agentd_dir/etc/agentd.conf

#create a private key and public key for the test user
cd $testdir
$vctool_binary -N -o test.priv keygen
$vctool_binary -k test.priv -o test.pub pubkey

#create a private key and public key for the endorser
cd $testdir
$vctool_binary -N -o endorser.priv keygen
$vctool_binary -k endorser.priv -o endorser.pub pubkey

#create a private key for agentd
mkdir -p $agentd_dir/priv
mkdir -p $agentd_dir/pub
cd $agentd_dir/priv
$vctool_binary -N -o agentd.priv keygen
$vctool_binary -k agentd.priv -o agentd.pub pubkey
chown veloagent:veloagent agentd.priv
cp agentd.pub $testdir
cp $testdir/test.pub $agentd_dir/pub
chown veloagent:veloagent $agentd_dir/pub/test.pub
cp $testdir/endorser.pub $agentd_dir/pub
chown veloagent:veloagent $agentd_dir/pub/endorser.pub

cd ..
echo "private key priv/agentd.priv" >> etc/agentd.conf
echo "" >> etc/agentd.conf
echo "endorser key pub/endorser.pub" >> etc/agentd.conf
echo "" >> etc/agentd.conf
echo "authorized entities {" >> etc/agentd.conf
echo "    pub/test.pub" >> etc/agentd.conf
echo "}" >> etc/agentd.conf

#run agentd with readconfig
cd $agentd_dir
bin/agentd readconfig > $testdir/readconfig_output.txt

#change to the test directory
cd $testdir

#verify that the endorser key is NOT in the output.
if grep -q "Endorser Key File:" readconfig_output.txt; then
    echo "Endorser Key File found."
else
    echo "Endorser Key File NOT found."
    exit 1
fi
