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

# print "jksdjksd:",(dirname abs_path $0),"\n";
my ($NL, $TAB) = ("\n","\t") ;

my %myopts = () ;
my $filter = 'ip proto 6 and \(  ';

sub Usage {
  print STDERR <<"END"
    사용법 : $0 -d dst_ip [ -p dst port ] [-s src ip ]
END
  ;
  exit ;
}

sub parse_arg {
  getopts("hs:d:p:", \%myopts) || Usage ;
  Usage if ($myopts{h} or ! $myopts{d});
  $filter .= " host $myopts{d} ";
  if ($myopts{s}) { $filter .= "or $myopts{s} " ;}
  $filter .= ' \) ';
  if ($myopts{p}) { $filter .= " and dst port $myopts{p} " ;}
}

my $EXECLSVC = "";
STDOUT->autoflush(0);
# my $CMD = './tcpdump.exe  -s 0 -Un -w - tcp and src 192.168.0 and dst 192.168.0.202 ' ;
my $CMD = 'tcpdump.exe  -s 0 -Un -w -  ' ;

parse_arg() ;

$SIG{INT} = \&endproc ;
$SIG{USR1} = \&endproc ;
$SIG{KILL} = \&endproc ;

my %svcgb ;
open (my $FF, "svcgbn");
while (<$FF>) {
  my ($k,$v) = split ;
  $svcgb{$k}=$v ;
}
close $FF;
$CMD .= $filter ;
my $pipe = IO::Pipe->new() ;
$pipe->reader($CMD ) ;
# binmode $pipe,":raw";
open(STDERR, ">/dev/null") ;

my $ymd = strftime "%Y%m%d", localtime;
print STDERR "log/aqtRealrcv_$ymd.log",NL;
open(my $FE,">>",LOGD."/aqtRealrcv_$ymd.log") || die "logfile open error :$?\n" ;
$FE->autoflush(1) ;

print $FE "$NL** AQT Receive Start job ", get_date() ," **$NL";
print $FE "cmd => $CMD **$NL";

my $LGB = "\n";
my ($tcnt,$sysgb) = (0,0);
my %pdata = ();
my %pdatac = ();
my %fdata = ();
my $rcnt = 0;
my $rdata ;
my ( $srcip, $dstip, $ky, $svuuid, $sdata, $sdata2 );

read ($pipe, $rdata, 24) ;
# printf "%02x " , ord for $rdata =~ /./g ;
# print NL;
while( read($pipe, $rdata,16) ) {
  my ($ts_sec, $tsusec, $caplen, $origlen) = unpack("L4", $rdata) ;
  read($pipe, $rdata, $caplen) ;
  # next if ($caplen < 114) ;
  my $strdate = strftime "%F %H:%M:%S", localtime($ts_sec) ;
  $strdate .= sprintf('.%06d', $tsusec) ;
  print STDERR "$strdate : $tsusec : " ;
  print STDERR "Packet length -> $caplen, $origlen",NL ;

  my ($foo1,$tlen,$id,$foff, $foo2, $sip, $dip, $dport,$sport,$seqno,$ackno,$foo3,$checksum,$upoint,$nextsq) ;
   ($foo1,$tlen,$id,$foff, $foo2, $sip, $dip, $sport,$dport,$seqno,$ackno,$foo3,$checksum,$upoint)
   = unpack("n4 N N2 n2 N2 A4 n2 ", substr($rdata,14)) ;

   ($srcip, $dstip) = ( inet_ntoa(pack 'N' ,$sip), inet_ntoa(pack 'N' ,$dip) ) ;
   my ($thlen, $flag) = unpack( "C C",$foo3 ) ;
   $thlen >>= 4 ;
   $thlen *= 4  ;
   # printf "%02x " , ord for $foo3 =~ /./g ;
   print STDERR " * tcp header len :  $thlen ",NL  ;
   print STDERR NL," $srcip:$sport -> $dstip:$dport, $tlen ",NL ;
   next if ( $tlen <= (20 + $thlen )) ;
   $sdata = '';
   $sdata = unpack("a$tlen", substr($rdata, (14 + 20 + $thlen )) ) ;
   next unless ( getAbit($flag,4) == 1  && $sdata =~ /HTTP/) ;
   # id, fragmaent , offset
   my $frag = getAbit($foff,2);

   $foff &= 0x1fff ;
   printf STDERR " foff : %x, id:%d, frag(%d)%s", $foff, $id, $frag,NL;
   # $sdata =~ s![^[:print:]]!\.!g ;

   if ( $sdata !~ /^HTTP/ ) {
     $sdata = pack("A30 n A30 n A30 N2 A*", $srcip,$sport, $dstip,$dport,$strdate, $seqno,$ackno, $sdata) ;
     $nextsq = $seqno + $tlen - (20 + $thlen ) ;
     $ky = sprintf("%s:%d:%d" , $dstip,$dport,$nextsq) ;
     $pdata{$ky} = $sdata ;
     next ;
   } else {
     $ky = sprintf("%s:%d:%d" , $srcip,$sport,$ackno) ;
     if ( $pdata{$ky} ) {
       $pdata{$ky} .=  pack("A2 A30 A*", '@@',$strdate, $sdata) ;
       printf "%08d",length($pdata{$ky}) ;
       print $pdata{$ky} ;
       STDOUT->flush() ;
       delete $pdata{$ky} ;
       undef $pdata{$ky} ;
     }
   }
   # print NL,"$seqno,$ackno : ",$tlen - (20 + $thlen ) ,",  $caplen, $origlen",NL ;
   # printf "URG(%d) ACK(%d) PSH(%d) RST(%d) SYN(%d FIN(%d)", getAbit($flag,2),getAbit($flag,3),getAbit($flag,4),getAbit($flag,5),getAbit($flag,6),getAbit($flag,7) ;
   # print NL ;

}

&endproc ;

sub pdata_check {
  my $k = shift ;
  if ($pdata{$k}){
    $pdatac{$k}++ ;
    my $svcid = substr($pdata{$k},72,15) ;
    next if ($myopts{r} && $svcid =~ /r$/ ) ;
    if ( $EXECLSVC =~ /\Q$svcid/s || $svcid !~ /\w{15}/ ){
      delete $pdata{$k}, $pdatac{$k}, $fdata{$k} ;
      undef $pdata{$k} ;
      return ;
    }
    $sysgb = $svcgb{$svcid} ;
    $sysgb = $k =~ m'172,17,235.5' ? "2" : "1"  unless $svcgb{$svcid} ;
    my $len = substr($pdata{$k},0,8) + 8 ;
    $pdata{$k} .= $fdata{$k} if $fdata{$k} ;
    if ($len > 200 && $len <= length($pdata{$k})) {
      $tcnt++;
      print pack("a1 a$len a1", $sysgb, $pdata{$k}, $LGB);
      delete $pdata{$k}, $pdatac{$k}, $fdata{$k} ;
      undef $pdata{$k} ;
      return ;
    } elsif ($ky ne $k) {
    	return ;
    }
  }
}

sub pdata_out {
  foreach my $k (keys(%pdata)) {
    pdata_check($k) ;
  }
}

sub print_data {
  my $svcid = substr($sdata,72,15);
  $svcid =~ s!\s!!g ;

  return if ($svcid !~ /\w{15}/  || $EXECLSVC =~ /$svcid/) ;
  return if ( $myopts{r} && $svcid =~ /r$/ );

  my $sysgb = $svcgb{$svcid} ;
  $sysgb = ($dstip =~ m'172.17.235.5') ? "2" : "1"  unless $svcgb{$svcid} ;

  return if ( $sdata !~ /^00\d{6}R/ ) ;
  my $len = substr($sdata,0,8) + 8 ;
  $tcnt++ ;
  print pack("a1 a$len a1", $sysgb, $sdata, $LGB) ;
  return 1;
}

sub data_check {
  if ( $sdata !~ /^00\d{6}R/ ) {
    $fdata{$ky} .= $sdata ;
    return 1;
  }
  my $len = substr($sdata,0,8) + 8 ;
  if ( $len > length($sdata ) ) {
    $pdata{$ky} = $sdata ;
    $fdata{$ky} = "";
  } else {
    print_data ;
  }
  return 0 ;
}

sub endproc {
  $pipe->close();
  print $FE "** AQT Receive end job $tcnt 건 ", get_date, " **$NL";
  close $FE ;
  exit ;
}
