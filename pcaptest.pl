use strict;
use warnings;

use Net::TcpDumpLog;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;

my $log = Net::TcpDumpLog->new();
$log->read("test01.pcap");

foreach my $index ($log->indexes) {
  my ($length_orig, $length_incl, $drops, $secs, $msecs) = $log->header($index);
  my $data = $log->data($index);

  my $eth_obj = NetPacket::Ethernet->decode($data);
  next unless $eth_obj->{type} == NetPacket::Ethernet::ETH_TYPE_IP;

  my $ip_obj = NetPacket::IP->decode($eth_obj->{data});
  next unless $ip_obj->{proto} == NetPacket::IP::IP_PROTO_TCP;

  my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($secs + $msecs/1000);
  print sprintf("%02d-%02d %02d:%02d:%02d.%d",
    $mon, $mday, $hour, $min, $sec, $msecs),
    " ", $eth_obj->{src_mac}, " -> ",
    $eth_obj->{dest_mac}, "\n";
  print "\t", $ip_obj->{src_ip}, ":", $tcp_obj->{src_port},
    " -> ",
    $ip_obj->{dest_ip}, ":", $tcp_obj->{dest_port}, "\n";
}
