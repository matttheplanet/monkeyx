#!/bin/bash

if [[ $# -ne 1 ]] ; then
    echo 'Processes files from Monkeyax standard workflow for easy remote copying.'
	echo 'This must be run from the same directory monkeyax was run in.'
    echo -e '\nPlease specify the monkeyax output prefix used as positional argument. Usage: '
    echo -e "bash ~/monkeyax/utils/process-stdworkflow-files.sh {output-prefix}\n"
    exit 0
fi

prefix="$1"
mkdir "results-$prefix"
cp *.txt -t "results-$prefix"
cp "$prefix-baselinescan.xml" -t "results-$prefix"
cp "$prefix-tcpfull.xml" -t "results-$prefix"
cp "$prefix-tcpfull.xml" -t "results-$prefix"
cp "$prefix-udp1024.xml" -t "results-$prefix"
cat *-alive-hosts.txt | sort -fuV >> "results-$prefix"/all-alive-hosts.txt
cp -r "$prefix-gowitness-TCPfull" -t "results-$prefix"
echo "Done copying files into results-$prefix."
echo -e "scp command to use:\n\t tsh scp -r ubuntu@ax-controller:`pwd`/results-$prefix ."
