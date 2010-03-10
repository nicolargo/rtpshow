#!/usr/bin/perl
#
# RTPSHOW
# Nicolas Hennion - 03/2010
#
# Syntax: sudo ./rtpshow.pl eth0
#
#==================================================
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301,  USA
#
#==================================================
#
# TODO
# - Gestion des erreurs (par exemple lors du décodage des paquets)
# - Unite pour la gigue ? TBC
#
my $program_name = "RTPshow";
my $program_version =  "0.6";

# Libraries
use Getopt::Std;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use Net::RTP::Packet;
use Time::HiRes qw( time);
use strict;

# Globals variables
my $promisc = 1;                    # Promiscius mode enable
my $mtu = 1500;                      # MTU size for Ethernet packet (default is 1500)
my $proto="udp";                    # Protocol (UDP or TCP, UDP is default)
my $port;                                  # Port  to listen
my $err;                                    # Error code
my $report_timer = 0;           # Timer for report display
my $report_delay = 1;           # Set the delay between report display (default 1s)
my $report_end; 
my $report_counter = 0;
my %packet_matched;          # Number of RTP packets matched
my %jitter;                               # Variables used for Jitter calculation
my %jitter_sum;
my %jitter_avg;
my %jitter_max;
my %time_ts_i;
my %time_ta_i;
my %time_ts_j;
my %time_ta_j;
my %bitrate;                           # Variables used for the bitrate calculation
my %bitrate_sum;
my %bitrate_avg;
my %bitrate_max;
my %datasize = 0;

# Programs argument management
my %opts = ();
getopts("hvp:i:tm:s:", \%opts);
if ($opts{v}) {
    # Display the version
    print "$program_name $program_version\n";
    exit(-1);
}

my $p_tag=($opts{p})?1:0;
if ($opts{h} | !($p_tag)) {
    # Help
    print "$program_name $program_version\n";
    print "usage (as super user): ", $program_name," [options]\n";
    print " -h: Print the command line help\n";
    print " -v: Print the program version\n";
    print " -p port: Listen RTP packets on this port (mandatory)\n";
    print " -i interface: Listen on interface (default is auto-discover)\n";
    print " -t: Listen RTP over TCP packets  (default is UDP)\n";
    print " -m mtu: Set the MTU size for Ethernet packets (default 1500)\n";    
    print " -s sec: Set the delay in second between report (default 1 )\n";    
    exit (-1);
}
# Get MTU (default is 1500)
if ($opts{m}) {
    $mtu = $opts{m};
}
# Get the port (mandatory)
if ($opts{p}) {
    $port = $opts{p};
}
# Get the protocol (UDP by default or TCP)
if ($opts{t}) {
    $proto = "tcp";
}
# Get the delay between report
if ($opts{s}) {
    $report_delay = $opts{s};
}

# Use interface passed in program arguments
# if no argument is passed, determine an appropriate network 
my $dev = $opts{d};
unless (defined $dev) {
    $dev = Net::Pcap::lookupdev(\$err);
    if (defined $err) {
        die 'Unable to determine network device for monitoring - ', $err;
    }
}

#   Look up network address information
my ($address, $netmask);
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}

#   Create packet capture object on device
my $object;
$object = Net::Pcap::open_live($dev, $mtu, 0, $promisc, \$err);
unless (defined $object) {
    die 'Unable to create packet capture on device ', $dev, ' - ', $err;
}

#   Compile and set packet filter for packet capture 
my $filter;
Net::Pcap::compile(
    $object, 
    \$filter, 
    '('.$proto.' dst port '.$port.')', 
    0, 
    $netmask
) && die 'Unable to compile packet capture filter';
Net::Pcap::setfilter($object, $filter) &&
    die 'Unable to set packet capture filter';

#   Set callback function and initiate packet capture loop
Net::Pcap::loop($object, -1, \&rtp_packets, '') ||
    die 'Unable to perform packet capture';

# End of the capture
Net::Pcap::close($object);

# This function decode the RTP packet
sub rtp_packets {
    my ($user_data, $header, $packet) = @_;
    
    #   Strip ethernet encapsulation of captured packet 
    my $ether_data = NetPacket::Ethernet::strip($packet);
    #   Strip ip encapsulation
    my $ip = NetPacket::IP->decode($ether_data);
    my $udportcp;
    if ($proto eq "udp") {
        #   Strip udp encapsulation
        $udportcp = NetPacket::UDP->decode($ip->{'data'});
    } elsif ($proto eq "tcp") {
        #   Strip tcp encapsulation
        $udportcp = NetPacket::TCP->decode($ip->{'data'});
    }
    #   Strip rtp encapsulation
    my $rtp = new Net::RTP::Packet();
    $rtp->decode($udportcp->{'data'});
    if (!defined $rtp->version()) { 
        print "Is not a RTP packet (skip)\n"; 
        return;
    }
    
    # Get the Ssrc
    my $ssrc = $rtp->ssrc();

    # Increment the packet matched
    $packet_matched{"$ssrc"} += 1;
    
   # Set time of arrival for packet
   $time_ta_j{"$ssrc"} = time;
   
   # Get timestamp for packet i (t-1) and j (t) 
   $time_ts_j{"$ssrc"} = $rtp->timestamp();        
    
    # Compute Jitter (based on RFC 1889)
    my $difference;
    if ($time_ta_i{"$ssrc"} != 0) {
        $difference = ($time_ta_j{"$ssrc"} - $time_ta_i{"$ssrc"}) - ($time_ts_j{"$ssrc"} - $time_ts_i{"$ssrc"});
        $jitter{"$ssrc"} = $jitter{"$ssrc"}+(abs($difference)-$jitter{"$ssrc"})/16.0;
        $jitter_sum{"$ssrc"} += $jitter{"$ssrc"};
        $jitter_avg{"$ssrc"} =  $jitter_sum{"$ssrc"} / $packet_matched{"$ssrc"};
        if ($jitter{"$ssrc"} > $jitter_max{"$ssrc"}) {
            $jitter_max{"$ssrc"} = $jitter{"$ssrc"};
        }
    }

    # Save packet TA and TS
    $time_ta_i{"$ssrc"} = $time_ta_j{"$ssrc"};
    $time_ts_i{"$ssrc"} = $time_ts_j{"$ssrc"};
    
    # Data size (header are not included)
    $datasize{"$ssrc"} += $rtp->size();
        
    #   Print the report every report_delay seconds
    if ($report_timer == 0) {
        $report_timer = time;
        $report_end = $report_timer + $report_delay;
    }
    $report_timer = time;
    if ($report_timer > $report_end) {
        $report_counter += 1;
        $report_end = $report_timer + $report_delay;
        
        # Bitrate calculation
        $bitrate{"$ssrc"} = ($datasize{"$ssrc"}*8) / $report_delay;
        $datasize{"$ssrc"} = 0;
        $bitrate_sum{"$ssrc"} += $bitrate{"$ssrc"};
        $bitrate_avg{"$ssrc"} = $bitrate_sum{"$ssrc"} / $report_counter;
        if ($bitrate{"$ssrc"} > $bitrate_max{"$ssrc"}) {
            $bitrate_max{"$ssrc"} = $bitrate{"$ssrc"};
        }
        
        # Display report
        my $ssrckey;
        foreach $ssrckey (sort keys %bitrate) {
            print "RTP report for the ssrc ", $ssrckey, " flow\n";
            printf " Bitrate Kbps (current / average / max): %.0f / %.0f / %.0f\n", $bitrate{"$ssrckey"}/1000, $bitrate_avg{"$ssrckey"}/1000, $bitrate_max{"$ssrckey"}/1000;
            printf " Jitter ms (current / average / max): %.0f / %.0f / %.0f\n", $jitter{"$ssrckey"}/1000, $jitter_avg{"$ssrckey"}/1000, $jitter_max{"$ssrckey"}/1000;
        }
    }
}
