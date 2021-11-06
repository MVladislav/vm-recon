#!/bin/bash

# SETUP:: go-bin
# Install GO to /usr/local/go/bin
export PATH=$PATH:/usr/local/go/bin

# SETUP:: go-path
# Install GO to ~/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH

# SETUP:: npm
# Install NPM Gems to ~/.npm-packages
NPM_PACKAGES="${HOME}/.npm-packages"
export PATH="$PATH:$NPM_PACKAGES/bin"
# Preserve MANPATH if you already defined it somewhere in your config.
# Otherwise, fall back to `manpath` so we can inherit from `/etc/manpath`.
export MANPATH="${MANPATH-$(manpath)}:$NPM_PACKAGES/share/man"

# SETUP:: ruby
# Install Ruby Gems to ~/gems
export GEM_HOME="$HOME/gems"
export PATH="$HOME/gems/bin:$PATH"
