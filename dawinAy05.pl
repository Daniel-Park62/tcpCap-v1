#! /usr/bin/perl
use strict;
use Getopt::Std ;

my %myopts = ();

sub Usage {
  print STDERR5<<'ENDL'
    사용법 : $0 diff결과파일...
ENDL
  exit ;
}

sub parse_arg {
  getopts("h", \%myopts) || Usage ;
}

sub file_anal {
  my $filenm = shift || return ;
  my ($src1,$src2,$f1n, $f2n, $cnt1, $cnt2) = ("","","","",0,0) ;
  
  open(my $FD,"<", $filenm) || print STDERR "$? $filenm\n" && return ;
  LOOP1 : while(my $stext =<$FD>)
  {
    if ( $stext =~ /^filename\[(.*?)\]\[(.*?)\]/) {
      if ( length $f1n > 0 or length $f2n > 0 or substr($src2,0,2) eq "##" ) {
        my $flnm = $src1 =~ s!.*/!!r ;
        $f1n =~ s!["\t\r! !gs ;
        $f2n =~ s!["\t\r! !gs ;
        print qq($flnm \t$src1 \t"$f1n"\t$src2 \t"$f2n"\n) ;
      }
      ($f1n, $f2n, $cnt1, $cnt2) = ("","",0,0) ;
      ($src1,$src2) = ($1,$2) ;
      next LOOP1;
    }
    if ( $stext =~ /^\>(.*)$/) {
      next LOOP1 if ($cnt2 > 20) ;
      $cnt2++ ;
      $f2n .= ($f2n ? "@@":""). $1 ;
      next LOOP1 ;
    }
    if ( $stext =~ /^\<(.*)$/) {
      next LOOP1 if ($cnt1 > 20) ;
      $cnt1++ ;
      $f1n .= ($f1n ? "@@":""). $1 ;
    }
  }
  close $FD ;
}

parse_arg ;
my @infiles = map { glob } @ARGV if ( @ARGV > 0 ) ;

foreach my $ifile (@infiles)
{
  chomp($ifile);
  print STDERR "$ifile read \n" ;
  file_anal($ifile);
}
    
