#!/bin/bash
# Install iptables extension libraries via the Makefile iinstall target.
# DKMS runs this from the package source directory after module install.
set -e
make iinstall
