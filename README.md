Integration Tests for the Velochain C Libraries
===============================================

These integration tests set up an agentd instance so that features of the
Velochain C blockchain library can be tested against a live blockchain instance.

Since agentd must run as root, these tests must be started as root. In later
versions of agentd, we will make use of the OS capabilities in Linux or OpenBSD
to reduce or eliminate the need to run agentd as root. But, for now, agentd uses
generic system calls like `chroot` that require root access, and thus, it checks
to ensure that it is running at effective UID 0.

The tests themselves run as a shell script. This shell script checks for the
existence of a `/opt/integration_tests` directory that is owned by root. This
can be a regular directory, a symlink, a hard link, or a mount point for another
filesystem. This directory will be used for staging and running the tests. At
the beginning of the test phase, everything in this directory will be deleted.

The main shell script first starts running as the user before requesting sudo
access to run the test script itself. While running as the current user, it will
configure and build the Velo C Blockchain library, agentd, and the integration
test binaries. These will all be copied to `/opt/integration_tests/staging`.  A
unique directory for each testing scenario will be created so that agentd can be
installed and started, and the tests can be run.

To run the integration tests, as a non-root user, execute
`./run_integration_tests.sh`. Once the tests have finished building, you will be
prompted to enter your user password to sudo to root, unless your sudoers entry
does not require a password.  Each test will run in sequence, with some test
output provided to the terminal.
