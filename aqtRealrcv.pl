#!/usr/bin/perl

# AQT TCPDUMP

use strict;
use Getopt::Std ;
use bytes ;
use File::Spec;
use IO::Pipe ;
use open IO => ':raw' ;
use threads;
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
my $filter = "'ip proto 6 and ( ";

sub Usage {
  print STDERR <<"END"
    사용법 : $0 -d dst_ip [ -p dst port ] [-s src ip ]
END
  ;
  exit ;
}

# my $CMD = './tcpdump.exe  -s 0 -Un -w - tcp and src 192.168.0 and dst 192.168.0.202 ' ;
my $CMD = 'tcpdump.exe  -s 0 -Un -w -  ' ;

sub parse_arg {
  getopts("vhs:d:p:r:", \%myopts) || Usage ;
  Usage if ($myopts{h} );
  $filter .= " host $myopts{d} ";
  if ($myopts{s}) { $filter .= "or $myopts{s} " ;}
  $filter .= ' ) ';
  if ($myopts{p}) { $filter .= " and dst port (". $myopts{p} =~ s/,/ or /gr . ")" ;}
  $filter .= "'" ;
  $CMD = "tcpdump -r $myopts{r} -w - "  if ( $myopts{r} ) ;
}

my $EXECLSVC = "";
STDOUT->autoflush(0);

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
$CMD .= $filter  unless($myopts{r});
my $pipe = IO::Pipe->new() ;
$pipe->reader($CMD ) ;
# binmode $pipe,":raw";
open(STDERR, ">/dev/null") unless ($myopts{v});

my $ymd = strftime "%Y%m%d", localtime;
# print STDERR "log/aqtRealrcv_$ymd.log",NL;
open(my $FE,">>",LOGD."/aqtRealrcv_$ymd.log") || die "logfile open error :$?\n" ;
$FE->autoflush(1) ;

print $FE "$NL** AQT Receive Start job ", get_date() ," **$NL";
print $FE "cmd => $CMD **$NL";

my $LGB = "\n";
my ($tcnt,$sysgb) = (0,0);
my %pdata = ();
my $rcnt = 0;
my $rdata ;
my ( $srcip, $dstip, $ky, $svuuid, $sdata, $sdata2 );

read ($pipe, $rdata, 24) ;
# printf STDERR "%02x " , ord for $rdata =~ /./g ;
# print STDERR NL;
my $magic = unpack("L", $rdata);
print STDERR "OK!! ",NL if ( $magic == hex('A1B2C3D4')) ;

# my $t = threads->new(\&pdata_check,0);
# $t->detach() ;
LOOP1: while( read($pipe, $rdata,16) ) {
  my ($ts_sec, $tsusec, $caplen, $origlen) = unpack("L4", $rdata) ;
  read($pipe, $rdata, $caplen) ;
  # next if ($caplen < 114) ;
  my $strdate = strftime "%F %H:%M:%S", localtime($ts_sec) ;
  $strdate .= sprintf('.%06d', $tsusec) ;
  print STDERR NL,"** $strdate : Packet length -> $caplen, $origlen",NL ;

  my ($foo1,$tlen,$id,$foff, $foo2, $sip, $dip, $dport,$sport,$seqno,$ackno,$foo3,$checksum,$upoint,$nextsq) ;
   ($foo1,$tlen,$id,$foff, $foo2, $sip, $dip, $sport,$dport,$seqno,$ackno,$foo3,$checksum,$upoint)
   = unpack("n4 N N2 n2 N2 A4 n2 ", substr($rdata,14)) ;

   ($srcip, $dstip) = ( inet_ntoa(pack 'N' ,$sip), inet_ntoa(pack 'N' ,$dip) ) ;
   my ($thlen, $flag) = unpack( "C C",$foo3 ) ;
   $thlen >>= 4 ;
   $thlen *= 4  ;
  #  next if ( $tlen <= (20 + $thlen )) ;
   # printf "%02x " , ord for $foo3 =~ /./g ;
   print STDERR " * tcp header len :  $thlen ",NL  ;
   print STDERR " $srcip:$sport -> $dstip:$dport, total_plen ($tlen) ",NL ;
   $sdata = '';
   $sdata = unpack("a$tlen", substr($rdata, (14 + 20 + $thlen )) ) ;
  #  next unless ( getAbit($flag,4) == 1  && $sdata =~ /HTTP/) ;
   # id, fragmaent , offset
   my $frag = getAbit($foff,2);

   $foff &= 0x1fff ;
   printf STDERR " foff : %x, id:%d, frag(%d)%s", $foff, $id, $frag,NL;
   printf STDERR "[%d: %d] \n" , $seqno,$ackno ;
   # $sdata =~ s![^[:print:]]!\.!g ;

   if ( $sdata =~ /^(GET|POST|PUT|DELETE)/ ) {
     my $qdata = pack("A30 n A30 n A30 N2 A*", $srcip,$sport, $dstip,$dport,$strdate, $seqno,$ackno, $sdata) ;
     $nextsq = $seqno + $tlen - (20 + $thlen ) ;
     $ky = sprintf("%s:%d:%d" , $dstip,$dport,$nextsq) ;
     $pdata{$ky}{d} = $qdata ;
     $pdata{$ky}{r} = '';
     $pdata{$ky}{t} = time ;
     print STDERR $sdata if ( $sdata =~ /POST/);
     next ;
   } else {
     $ky = sprintf("%s:%d:%d" , $srcip,$sport,$ackno) ;
     if ( exists( $pdata{$ky} ) ) {
       if ( $sdata =~ /Content-Type:\s*image\b/s ) {
        $pdata{$ky} = () ;
        delete $pdata{$ky} ;
        next LOOP1;
       } 
       $pdata{$ky}{r} .= $sdata ;
       $pdata{$ky}{rt} = $strdate unless $pdata{$ky}{rt};
       if ( $sdata =~ /Content-Length:\s?(\d+)\s/s ) {
         $pdata{$ky}{l} = $1 ;
         $sdata =~ /^\r\n/ms and $pdata{$ky}{hl} = $+[0] ;
        #  print $pdata{$ky}{hl},":",substr($sdata,0,$pdata{$ky}{hl} + 20 ),$NL ;
       } 
      #  $pdata{$ky}{d} .=  pack("A2 A30 A*", '@@',$strdate, $sdata) ;
      #  printf "%08d",length($pdata{$ky}{d}) ;
      #  print $pdata{$ky}{d} ;
      #  STDOUT->flush() ;
      #  delete $pdata{$ky} ;
      #  undef $pdata{$ky} ;
     } else {
      printf  STDERR "*Not Found * %s:%d:%d \n" , $srcip,$sport,$ackno ;
     }
   } 

   # print NL,"$seqno,$ackno : ",$tlen - (20 + $thlen ) ,",  $caplen, $origlen",NL ;
   # printf "URG(%d) ACK(%d) PSH(%d) RST(%d) SYN(%d FIN(%d)", getAbit($flag,2),getAbit($flag,3),getAbit($flag,4),getAbit($flag,5),getAbit($flag,6),getAbit($flag,7) ;
   # print NL ;
  # 
}

# foreach my $k (keys(%pdata)) {
#   print "** NOT MATCH **", $pdata{$k},NL ;
# }

&endproc ;

sub pdata_check {
  my $sw = shift ;
  my $cnt = 0 ;
  while(1) {
    foreach my $k (keys(%pdata)) {
      $cnt++ ;
      my $ctime = time() ;
      # print "[$ctime : $pdata{$k}{t}]",$NL ;
      unless ($pdata{$k}{d} ) {
        $pdata{$k} = () ;
        delete $pdata{$k} ;
        next ;
      }
      next if ( ($ctime - $pdata{$k}{t}) < 5 and $sw == 0);
      $pdata{$k}{d} .=  pack("A2 A30 A*", '@@', $pdata{$k}{rt}, $pdata{$k}{r}) ;
      printf "%08d",length($pdata{$k}{d}) ;
      # printf " %08d %d %d",length($pdata{$k}{r}) ,$pdata{$k}{l} , length($pdata{$k}{r}) - $pdata{$k}{hl}  ;
      # print substr($pdata{$k}{d},102,700),$NL ;
      print $pdata{$k}{d} ;
      STDOUT->flush() ;
      $pdata{$k} = () ;
      delete $pdata{$k} ;
      # undef $pdata{$k} ;
      sleep(1);
    }
    last if ($sw) ;
    last unless ($cnt ) ;
  }

}


sub endproc {
  pdata_check(1) ;
  $pipe->close();
  print $FE "** AQT Receive end job $tcnt 건 ", get_date, " **$NL";
  close $FE ;
  exit ;
}
