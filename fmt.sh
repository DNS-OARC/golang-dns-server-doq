#!/bin/sh

gofmt -w *.go
sed -i -e 's%	%    %g' *.go
