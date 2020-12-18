use strict; use warnings;
use Exporter qw(import);
use POSIX qw(strftime);

our @EXPORT = qw(get_date getAbit);
use constant {
  NL => "\n",
  TAB => "\t",
  LOGD => "log",
};

sub get_date {
  my $dt = strftime "%F %H:%M:%S", localtime;
  return $dt ;
}
sub getAbit { # getbit()
  return ($_[0] & (1 << $_[1])) >> $_[1];
}

"bye" ;
