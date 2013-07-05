#!/bin/bash
#
# Refer to 'man yaws' to see various options that can be given to yaws on command line

#yaws --daemon --runmod start_applications --sname yaws --heart --conf ./yaws.conf --id application
yaws --daemon --sname wol --runmod wol_server --heart --conf ./yaws.conf --id wol

exit 0

