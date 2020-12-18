#!/isr/bin/perl

# AQT CONVERT

use strict;
use Getopt::Std ;
use bytes ;
use File::Spec;

my ($NL, $TAB) = ("\n","\t") ;

my %myopts = () ;

sub Usage {
  print STDERR <<"END"
    사용법 : $0 [-s oltpID]dk -o 결과dir [-n 서비스별건수] [-e fillter] input dir
        -d : 파일별서비스
        -e : 파일명 fillter
END
  exit ;
}

sub parse_arg {
  getopts("hdo:n:e:s:", \%myopts) || Usage ;
  Usage if ($myopts{h});
  if ( $myopts{n} && ( $myopts{n} != /\d+/ || $myopts{n} < 1)){
    print STDERR "-n 1 이상의 숫자를 선택하세요.\n" ;
    exit;
  }
}

sub get_date {
  my $dt = `date +"%F %R"` ;
  chomp $dt ;
  return $dt ;
}

parse_arg() ;
my $func = \&file_anal ;
my $pwd = qx(pwd);
chomp $pwd ;

my @tdir = <@ARGV> ;
if ( ! -d $tdir[0] ) {
  print SRDERR "INPUT DIR Check !\n" ;
  exit ;
}
open (my $FE,">","aqtConvert_$$.err") || die "$?" ;
my %svcarr ;

open (my $FO, ">", $myopts{o} ) || die "$? $myopts{o}";

print $FE "AQT CONVERTER Start job", get_date,"**$NL" ;
find( { wanted => $func}, @tdir) ;
print $FE "AQT CONVERTER End job", get_date,"**$NL" ;
close $FE ;
close $FO ;

sub file_anal{
    chomp ;
    return if ( -d || ! /\d{6}\.\d{5}$/ ) ;
    open(my $FI,"<",$_) || print STDERR "$? $_ $NL" && return ;
    local $/ = "]\n" ;
    my ($uuid, $svcid );
    %svcarr = () if ( $myopts{d} ) ;
    LOOP1: while ( my $stext=<$FI>)
    {
      if ( $stext =~ /InputData\[/ ) {
        my ($data1, $data2) split(/\n/,$stext) ;
        my @hdata = map { s/\s+$//; $_ } split(/\|/, $data1) ;
        $data2 =~ s!InputData\[(.*)\]$!$1!s ;
        $uuid = substr($data2,40,32) ;
        $uuid =~ s/\s+$// ;
        my $svrnm = $hdata[14];
        $svcid = $hdata[1];

        if ( $myopts{s} && $svcid !~ $myopts{s}) {
          <$FI>;
          next LOOP1 ;
        }
        if ( length $uuid < 32 || $myopts{n} && $myopts{n} <= $svcarr{$svcid}){
          <$FI> ;
          next LOOP1 ;
        }
        my $rtime = $hdata[0] ;
        my $stime = substr($hdata[0],0,8).substr($data2,104,9) ;
        $rtime = $stime if ($stime gt $rtime) ;
        my $userid = $hdata[5] ;
        my $clientip = $hdata[7] ;
        my $scrno = $hdata[4] ;
        my $slen = substr($data2,0,8) ;
        if ( $slen + 8 != length($data2) || length($svcid) < 15) {
          <$FI> ;
          next LOOP1 ;
        }
        print $FO join ("^^", $slen, $uuid, $svrnm, $svcid, $stime,$rtime,$userid,$clientip, $scrno, $data2) ;
      } else {
        $stext =~ s!OutputData\[(.*)\]\n!$1!s ;
        if ( substr($stext, 40,32) ne $uuid ) {
          print $FE $uuid," error Data !$NL";
          next LOOP1;
        }
        print $FO "^^",join("^^", substr(stext,0,8), substr($stext,251,4), substr($stext,255,80), $stext), "@@\n";
        $svcarr{$svcid}++  if ($myopts{n}) ;
      }
    }

    close $FI ;
    print $_, " END $NL";
}
