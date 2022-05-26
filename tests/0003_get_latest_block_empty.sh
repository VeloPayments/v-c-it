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

#create a private key and public key for the handshake test
cd $testdir
$vctool_binary -N -o test.priv keygen
$vctool_binary -k test.priv -o test.pub pubkey
$vctool_binary -N -o endorser.priv keygen
$vctool_binary -k endorser.priv -o endorser.pub pubkey

#create endorser config file
cat > endorse.cfg <<'endcfg'
entities {
    agentd
}

verbs for agentd {
    latest_block_id_get     c5b0eb04-6b24-48be-b7d9-bf9083a4be5d
    block_id_by_height_get  915a5ef4-8f96-4ef5-9588-0a75b1cae68d
    block_get               f382e365-1224-43b4-924a-1de4d9f4cf25
    transaction_get         7df210d6-f00b-47c4-a608-6f3f1df7511a
    transaction_submit      ef560d24-eea6-4847-9009-464b127f249b
    artifact_get            fc0e22ea-1e77-4ea4-a2ae-08be5ff73ccc
    assert_latest_block_id  447617b4-a847-437c-b62b-5bc6a94206fa
    sentinel_extend_api     c41b053c-6b4a-40a1-981b-882bdeffe978
}

roles for agentd {
    reader {
        latest_block_id_get
        block_get
        transaction_get
        artifact_get
        assert_latest_block_id
    }

    submitter extends reader {
        transaction_submit
    }

    extended_sentinel extends reader {
        sentinel_extend_api
    }
}
endcfg

#create a private key for agentd
mkdir -p $agentd_dir/priv
mkdir -p $agentd_dir/pub
cd $agentd_dir/priv
$vctool_binary -N -o agentd.priv keygen
$vctool_binary -k agentd.priv -o agentd.pub pubkey
chown veloagent:veloagent agentd.priv
cp agentd.pub $testdir
cp $testdir/endorser.pub $agentd_dir/pub
chown veloagent:veloagent $agentd_dir/pub/endorser.pub
chmod u+rw,g+r,o+r $agentd_dir/pub/endorser.pub

cd ..
echo "endorser key pub/endorser.pub" >> etc/agentd.conf
echo "private key priv/agentd.priv" >> etc/agentd.conf
echo "" >> etc/agentd.conf
echo "authorized entities {" >> etc/agentd.conf
echo "    pub/test.pub.endorsed" >> etc/agentd.conf
echo "}" >> etc/agentd.conf

cd $testdir
$vctool_binary -Dagentd=agentd.pub -k endorser.priv -i test.pub \
    -o test.pub.endorsed -E endorse.cfg -P agentd:latest_block_id_get endorse
cp $testdir/test.pub.endorsed $agentd_dir/pub
chown veloagent:veloagent $agentd_dir/pub/test.pub.endorsed

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
cp $build_dir/src/test_get_latest_block_empty/test_get_latest_block_empty .

#run the test
./test_get_latest_block_empty

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
