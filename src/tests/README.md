# firewalld testsuite

This is the firewalld testsuite. It consists of standalone autotest scripts
that can be run from any location.

# Example usage
The tests can be run from any location. They generate output in the current
directory so it's suggested to run them from `/tmp`. Tests must be run as root.

## Standard tests
The standard testsuite is run inside temporary network namespaces. As such
they're non-destructive to the host and may be run while firewalld is running
on the host.

To run the tests serially:
```sh
cd /tmp
```
```sh
/usr/share/firewalld/testsuite/testsuite
```
To run the tests in parallel:
```sh
/usr/share/firewalld/testsuite/testsuite -j4
```
To run a test for a specific bug use a keyword:
```sh
/usr/share/firewalld/testsuite/testsuite -k rhbz1404076
```
```sh
/usr/share/firewalld/testsuite/testsuite -k gh366
```
## Integration tests
The integration tests are destructive and require that at least firewalld and
NetworkManager are _not_ running on the host.

These tests _must_ be run serially:
```sh
cd /tmp
```
```sh
/usr/share/firewalld/testsuite/integration/testsuite
```
