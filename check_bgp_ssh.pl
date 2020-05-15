#!/usr/bin/perl -w
################# 
#
# check_bgp_ssh - nagios plugin 
#
# 
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.#
# 
#
# Requirements : 
#	- perl -MCPAN -e 'install Net::OpenSSH'
#	- perl -MCPAN -e 'install Regexp::IPv4' 
#	- perl -MCPAN -e 'install Switch' 
#
# Tested on :
#	- Cisco ASR 1000 Series Routers (ASR1006)
#   - Cisco 1841
################


use warnings;
use lib "."  ;
use utils qw($TIMEOUT %ERRORS &print_revision &support);
use vars qw($PROGNAME);

use Switch ;
use Net::OpenSSH;
use Regexp::IPv4 qw($IPv4_re);


# Just in case of problems, let's not hang Nagios
$SIG{'ALRM'} = sub {
        print ("ERROR: Plugin took too long to complete (alarm)\n");
        exit $ERRORS{"UNKNOWN"};
};
alarm($TIMEOUT);

$PROGNAME = "check_bgp_ssh.pl";
sub rntrim($);
sub print_help ();
sub print_usage ();

my ($opt_h,$opt_V);
my $login = "";
my $passwd = "";
my ($hostname,$status,$as,$up);

use Getopt::Long;
&Getopt::Long::config('bundling');
GetOptions(
	"V"   => \$opt_V,       "version"    => \$opt_V,
        "h"   => \$opt_h,       "help"       => \$opt_h,        
        "H=s" => \$hostname,    "hostname=s" => \$hostname,
        "L=s" => \$login,       "login=s" => \$login,
        "P=s" => \$passwd,      "password=s" => \$passwd,
);

# -h & --help print help
if ($opt_h) { print_help(); exit $ERRORS{'OK'}; }
# -V & --version print version
if ($opt_V) { print_revision($PROGNAME,'$Revision: 1.0 $ '); exit $ERRORS{'OK'}; }
# Invalid hostname print usage
if (!utils::is_hostname($hostname)) { print_usage(); exit $ERRORS{'UNKNOWN'}; }

my $state = 'OK' ;
$cmd = "show bgp  ipv4 unicast summary";

$session = Net::OpenSSH -> new($hostname, user => $login, password => $passwd, master_stdout_discard => 1, master_stderr_discard => 1, timeout => 7, 
master_opts => [-o => "StrictHostKeyChecking=no"]);
$session->error and $state = "WARNING" and print $state." : Unable to open ssh connection\n" and exit $ERRORS{$state};
@output = $session->capture($cmd);

my $msg = '';
my $count = 0;
my $countTotal = 0;

if (!@output) {
	$state = "WARNING";
	print "$state : Status retrieval failed. No result from connection \n";
	exit $ERRORS{$state};
}

my $nextline;


# Look for errors in output
# Sample output
#Line: 0 BGP router identifier 1.1.1.1, local AS number 12345
#Line: 1 BGP table version is 32, main routing table version 32
#Line: 2 3 network entries using 444 bytes of memory
#Line: 3 3 path entries using 192 bytes of memory
#Line: 4 2/2 BGP path/bestpath attribute entries using 272 bytes of memory
#Line: 5 1 BGP AS-PATH entries using 24 bytes of memory
#Line: 6 0 BGP route-map cache entries using 0 bytes of memory
#Line: 7 0 BGP filter-list cache entries using 0 bytes of memory
#Line: 8 BGP using 932 total bytes of memory
#Line: 9 Dampening enabled. 0 history paths, 0 dampened paths
#Line: 10 BGP activity 14/11 prefixes, 17/14 paths, scan interval 60 secs
#Line: 11
#Line: 12 Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
#Line: 13 1.2.3.4         4         12345      67      74       32    0    0 25:03:58      10000
#Line: 13 4.5.6.7         4         12345      67      74       32    0    0 25:03:58      10000

for ( my ($i, $currentline, $matchednei) = (0, '',0); $i <= $#output;    $i++ ) 
	{
	    $currentline = $output[$i];      
		if ($currentline =~ /invalid/) { 
			$state = "CRITICAL"; 
			print "$state : Error Command -> $output[$i]\n"; 
			exit $ERRORS{$state};
		}   
		# Skip till the line containing 'Neighbor'. The next lines contain the data.
		if ($currentline =~ /Neighbor/) { 
			$matchednei = 1 ;
			next ;
		}
		
		if (!$matchednei) {
		# Skip till the line contain Neighbor
			next;  
		}
		
		if ($currentline =~ /$IPv4_re/) {
								
			@info = split (/ +/,$currentline);
			
			$as = $info[2];
			$up = $info[8];
			$nei = $info[0];
			$status = $info[9];
			if ($info[10]) { $status = $status." ".$info[10]; }	
			$status=~ s/^\s+// ;
			$status = rntrim($status);			
			switch ($status) {
				case /Admin/ { 
						$state = $ERRORS{'WARNING'} >= $ERRORS{$state} ? 'WARNING' : $state ;
                        $msg = $msg . rntrim("WARNING: Neighbor $nei (AS$as) state is $status.") . "\n";
                            }
				case /Idle/ {
                        $state = $ERRORS{'CRITICAL'} >= $ERRORS{$state} ? 'CRITICAL' : $state ;
        				$msg = $msg . rntrim("CRITICAL: Neighbor $nei (AS$as) state is $status.") . "\n";
                       		}
				case /Active/ {
                        $state = $ERRORS{'CRITICAL'} >= $ERRORS{$state} ? 'CRITICAL' : $state  ;
        				$msg = $msg . rntrim("CRITICAL: Neighbor $nei (AS$as) state is $status.") . "\n";
                       		}
				case /^0$/ {
					    $state = $ERRORS{'WARNING'} >= $ERRORS{$state} ? 'WARNING' : $state ;
                        $msg = $msg . rntrim("WARNING : Neighbor $nei (AS$as) state is established. Established: $up. But 0 prefixes recieved") . "\n";
						}
				else {
					$state = $ERRORS{'OK'} >= $ERRORS{$state} ? 'OK' : $state ;
                    $msg = $msg . rntrim("OK : Neighbor $nei (AS$as) state is established. Established: $up. Prefix Received: $status") . "\n";					
					$count += 1 ;
					}			
			
			}
			$countTotal++;			
		}		
		
}

my $msgshort = "($count/$countTotal) BGP Peers Established.\n";
print $state.":".$msgshort.$msg;
exit $ERRORS{$state}; 


sub rntrim($)
{
	my $string = shift;
	$string =~ s/\r|\n//g;
	return $string;
}

sub print_help() {
        print_revision($PROGNAME,'$Revision: 1.0 $ ');
        print "This program is licensed under the terms of the\n";
        print "GNU General Public License\n(check source code for details)\n";
        print "\n";
        printf "Check BGP peer IPv6 status via SSH or Telnet on Cisco IOS.\n";
        print "\n";
        print_usage();
        print "\n";
        print " -H (--hostname)     Hostname to query - (required)\n";
        print " -L (--login)        Username - (optional: can be set in the script)\n";
        print " -P (--password)     Password - (optional: can be set in the script)\n";
		print " -V (--version)      Plugin version\n";
        print " -h (--help)         usage help\n";
        print "\n";
        support();
}

sub print_usage() {
        print "Usage: \n";
        print "  $PROGNAME -H <HOSTNAME> -L <login> -P <password>\n";
        print "  $PROGNAME [-h | --help]\n";
}


