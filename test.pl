#!/usr/bin/perl

# AQT TCPDUMP

use strict;
use Getopt::Std ;
use bytes ;
use File::Spec;
use IO::Pipe ;
use open IO => ':raw' ;
# use open ":std";
use Encode ;
use IO::Socket;
use socket ; # qw(inet_ntoa) ;
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib (dirname abs_path $0) . '/lib' ;
use dwcomm ;


print (dirname abs_path $0),NL ;
print get_date(),NL ;
my $sdt = strftime "%F %H:%M:%S", localtime ;
print $sdt ,NL ;
