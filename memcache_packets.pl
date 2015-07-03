#!/usr/bin/perl -w

# The MIT License (MIT)
#
# Copyright (c) 2015 Chris Zeeb
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

use strict;
use Net::Pcap qw( :functions );
use Time::HiRes qw( time );

my ($object, $key, $cnt, $byte_cnt, $perc, $avg_bytes, $start, $finish, $duration, $mbps, $total_cnt);

my $capture_packet_cnt = $ARGV[0] // 2000;

format STDOUT_TOP =
Duration: @#####.####s
$duration
Values returned: @<<<<<<<<<
$total_cnt
Memcache Key                                                  Count    Avg Bytes  Total Bytes  % of          Mbps
                                                                                                Throughput    
-----------------------------------------------------------------------------------------------------------------
.

format = 
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< @####### @######### @###########    @###.## @###.##
$key, $cnt, $avg_bytes, $byte_cnt, $perc, $mbps
.

my $err = '';
my $dev = pcap_lookupdev(\$err);

our $objects;
our $byte_total;

my $pcap = create_pcap();

$start = time;
pcap_loop($pcap, $capture_packet_cnt, \&process_packet, "Just for the demo");
$finish = time;
$duration = $finish - $start;

pcap_close($pcap);

foreach $key (sort { $objects->{$a}->{byte_count} <=> $objects->{$b}->{byte_count} } keys %{$objects}) {
  $object = $objects->{$key};
  $cnt = $object->{count};
  $byte_cnt = $object->{byte_count}; 
  $avg_bytes = $byte_cnt / $cnt;
  $perc = $byte_cnt/$byte_total*100;
  $mbps = sprintf('%.2f', $byte_cnt * 8 / $duration / 1024 / 1024);
  write();
}

sub process_packet {
  my ($user_data, $header, $packet) = @_;

  my ($key, $flag, $len);
  if(substr($packet, 66, 5) eq 'VALUE') {
    $packet =~ /VALUE ([^ ]+) (\d+) (\d+)/;
    $key = $1;
    $flag = $2;
    $len = $3;

    return unless $key;

    $objects->{$key}->{len} = $3 unless $objects->{$key}->{len};
    $objects->{$key}->{count}++;
    $objects->{$key}->{byte_count} += $3;
    $byte_total += $len;
    $total_cnt++;
  }
}

sub create_pcap {
  my $promisc = 0;   # We're only looking for packets destined to us,
                       # so no need for promiscuous mode.
  my $snaplen = 135; # Allows a max of 80 characters in the domain name

  my $to_ms = 0;			# timeout
  my $opt=1;                          # Sure, optimisation is good...
  my($err,$net,$mask,$dev,$filter_t);

  my $filter = "src port 11211";

  # Look up an appropriate device (eth0 usually)
  $dev = Net::Pcap::lookupdev(\$err);
  $dev or die "Net::Pcap::lookupdev failed.  Error was $err";
    
  if ( (Net::Pcap::lookupnet($dev, \$net, \$mask, \$err) ) == -1 ) {
      die "Net::Pcap::lookupnet failed.  Error was $err";
  }
    
  # Actually open up our descriptor
  my $pcap_t = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);
  $pcap_t || die "Can't create packet descriptor.  Error was $err";
  
  if ( Net::Pcap::compile($pcap_t, \$filter_t, $filter, $opt, $net) == -1 ) {
      die "Unable to compile filter string '$filter'\n";
  }

  # Make sure our sniffer only captures those bytes we want in
  # our filter.
  Net::Pcap::setfilter($pcap_t, $filter_t);

  # Return our pcap descriptor
  return $pcap_t;  
}
