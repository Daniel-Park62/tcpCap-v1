#!/isr/bin/perl

# ASW ED03

use strict;
use Getopt::Std ;
use File::fIND ;

my ($NL, $TAB, $RESET, $RED) = ("\n","\t","\x1b[m" "\x1b[0;31m") ;

my %myopts = () ;

sub Usage {
  print STDERR <<"END"
    사용법 : $0 -i 입략dir -o 결과dir -s 이중관리소스dir
END
  exit ;
}

sub parse_arg {
  getopts("hi:o:s:", \%myopts) || Usage ;
  Usage if ($myopts{h});
  if ( ! -d $myopts{i} )
    print STDERR $RED,"입력DIR invalid !!", $RESET,$NL ;
    exit;
  }

  if ( $myopts{i} eq $myopts{o})
    print STDERR $RED,"입력-결과 디렉토리가 같습니다. !!", $RESET,$NL ;
    exit;
  }
}

sub get_date {
  my $dt = `date +"%F %R"` ;
  chomp $dt ;
  return $dt ;
}

parse_arg ;
my $asReg = qr![ \t]*/\*\s*INFRA2020_ASIS.*?\n(.+?)\s*?\*/!s ;
my $toReg = qr!(.{20,150})(\n[ \t]*//\s*INFRA2020_TOBE_START.*?//\s*INFRA2020_TOBE_END.*?\n)(.{50,150})!s ;
my $toRegL = qr!(.{20,150})(\n[^\n]*?//\s*INFRA2020_TOBE[^\n_]*?\n)(.{50,150})!s ;
my $func = \&file_anal ;
my $pwd = qx(pwd);
chomp $pwd ;
print $pwd," <= pwd\n";

open(my $FE,">","./$$.err") || die "$? " ;

print $FE "** ASW EDITOR start job ", get_date, " **$NL";
find({ wanted => $func}, $myopts{i}) ;
print $FE "** ASW EDITOR end job ", get_date, " **$NL";
close $FE ;

sub file_anal {
  return if ( -d $_ ) ;
  my $flst = `find $pwd"/"$myopts{s} -name $_` ;
  chomp $flst ;
  return unless ( -e $flst) ;
  open(my $FD,"<",$flst) || print STDERR "$? \n" && return ;
  local $/;
  my $stext = <$FD> ;
  close $FD ;
  $stext =~ s/\r\n/\n/g ;
  open (my $FI,"<",$_) || print STDERR "$? \n" && return ;
  my $itext = <$FI> ;
  close $FI ;

  my $sw = 0 ;
  my $stext2 $stext =~ s!$asReg!$1!gr ;
  while ( $stext2 =~ m!$toRegL!g)
  {
    my ($p1, $new, $p2) = ($1,$2,$3) ;
    $itext=~ s/\Q$p1/$p1$new/s or $itext =~ s/\Q$p2/$new$p2/s or $sw = 1;
  }
  while ( $stext2 =~ m!$toReg!sg)
  {
    my ($p1, $new, $p2) = ($1,$2,$3) ;
    $itext=~ s/\Q$p1/$p1$new/s or $itext =~ s/\Q$p2/$new$p2/s or $sw = 1;
  }
  while ( $stext2 =~ m!$asReg!sg)
  {
    my ($old, $new ) = ($1,$&) ;
    $itext=~ s/\Q$old/$new/s or $sw = 1;
  }

  print $FE $_,$NL if ($sw) ;
  my $flout = join ("/",$pwd,$myopts{o}, $_) ;
  open (my $FO,">",$flout) || print STDERR "$?\n" && return;
  print $FO $itext ;
  close $FO ;
  print $_,"END $NL" ;

}
