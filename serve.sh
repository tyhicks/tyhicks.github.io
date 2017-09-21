#!/bin/sh

# IMPORTANT: The Ruby web server will attempt to listen on an external
# interface. Only execute this script on a properly firewalled system or inside
# of container that can't reach the outside world.

bundle exec jekyll serve -H 0.0.0.0 --watch
