#!/bin/perl -w
#
# TcpDumpLog.pm - Net::TcpDumpLog library to read tcpdump/libpcap files.
#
# 17-Oct-2003   Brendan Gregg

package Net::TcpDumpLog;

use strict;
use vars qw($VERSION);
#use warnings;

$VERSION = '0.10';

# new - create the tcpdump object.
# 	An optional argument is the number of bits this OS uses to store
#	times (usually 32-bits (Oct 2003)). If an OS is using 64-bit values, 
#	then the actual tcpdump/libpcap file format changes - so this is
#	quite important. Currrntly only 32-bit and 64-bit times are supported.
#
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = {};

	my $bits = shift || 32;		# Default

	$self->{major} = undef;
	$self->{minor} = undef;
	$self->{zoneoffset} = undef;
	$self->{accuracy} = undef;
	$self->{dumplength} = undef;
	$self->{linktype} = undef;
	$self->{data} = [];
	$self->{length_orig} = [];
	$self->{length_inc} = [];
	$self->{drops} = [];
	$self->{seconds} = [];
	$self->{msecs} = [];
	$self->{count} = 0;

	if ($bits == 64) {
		$self->{bits} = 64;
	} else {
		$self->{bits} = 32;	# Default
	}

	bless($self,$class);
	return $self;
}

# read - read the tcpdump file into memory
#
sub read {
        my $self = shift;
        my $file = shift;
        my ($header,$length,$ident,$version,$linktype,$header_rec,
         $zoneoffset,$accuracy,$frame_length_inc,$frame_length_orig,
	 $frame_drops,$frame_seconds,$frame_msecs,$frame_data,
	 $skip,$pad,$major,$minor,$dumplength);
        $self->{count} = 0;
        my $num = 0;

        ### Open tcpdump file
        open(TCPDUMPFILE,"$file") ||
         die "ERROR: Can't read log $file: $!\n";

        ### Fetch tcpdump header
        $length = read(TCPDUMPFILE,$header,24);
        die "ERROR: Can't read from log $file\n" if $length < 24;

        ### Check file really is a tcpdump file
        ($ident,$major,$minor,$zoneoffset,$accuracy,$dumplength,
	 $linktype) = unpack('a4SSIIII',$header);
	if ($ident !~ /^\241\262\303\324/) {
	        die "ERROR: Not a tcpdump file $file\n";
	}

        ### Store values
        $self->{version} = $version;
        $self->{major} = $major;
        $self->{minor} = $minor;
        $self->{zoneoffset} = $zoneoffset;
        $self->{accuracy} = $accuracy;
        $self->{dumplength} = $dumplength;
        $self->{linktype} = $linktype;

        #
        #  Read all packets into memory
        #
        $num = 0;
        while (1) {
	
		if ($self->{bits} == 64) {
			#
			#  64-bit timestamps
			#

       		        ### Fetch record header
			$length = read(TCPDUMPFILE,$header_rec,24);

                	### Quit loop if at end of file
                	last if $length < 24;

			### Unpack header
                	($frame_seconds,$frame_msecs,$frame_length_inc,
			 $frame_length_orig) = unpack('QQII',$header_rec);
		} else {
			#
			#  32-bit timestamps
			#

	                ### Fetch record header
	                $length = read(TCPDUMPFILE,$header_rec,16);

	                ### Quit loop if at end of file
                	last if $length < 16;

			### Unpack header
                	($frame_seconds,$frame_msecs,$frame_length_inc,
			 $frame_length_orig) = unpack('IIII',$header_rec);

		}
		$length = read(TCPDUMPFILE,$frame_data,$frame_length_inc);

		$frame_drops = $frame_length_orig - $frame_length_inc;

                ### Store values in memory
                $self->{data}[$num] = $frame_data;
                $self->{length_orig}[$num] = $frame_length_orig;
                $self->{length_inc}[$num] = $frame_length_inc;
                $self->{drops}[$num] = $frame_drops;
                $self->{seconds}[$num] = $frame_seconds;
                $self->{msecs}[$num] = $frame_msecs;
                $self->{count}++;
                $num++;
        }

        close TCPDUMPFILE;
}

# indexes - return a list of index numbers for the packets.
#               indexes start at "0"
#
sub indexes {
        my $self = shift;
        my $max = $self->{count} - 1;
        return (0..$max);
}

# maxindex - return the index number for the last packet.
#               indexes start at "0"
#
sub maxindex {
        my $self = shift;
        my $max = $self->{count} - 1;
        return $max;
}

# header - return header data for a given index
#
sub header {
        my $self = shift;
        my $num = shift;
        return ($self->{length_orig}[$num],
                $self->{length_inc}[$num],
                $self->{drops}[$num],
                $self->{seconds}[$num],
                $self->{msecs}[$num]);
}

# data - return packet data for a given index
#
sub data {
        my $self = shift;
        my $num = shift;
        return $self->{data}[$num];
}

# version - return log file version
#
sub version {
        my $self = shift;
        return sprintf("%u.%u",$self->{major},$self->{minor});
}

# linktype - return linktype
#
sub linktype {
	my $self = shift;
	return sprintf("%u",$self->{linktype});
}

# zoneoffset - return zoneoffset
#
sub zoneoffset {
	my $self = shift;
	return sprintf("%u",$self->{zoneoffset});
}

# accuracy - return accuracy
#
sub accuracy {
	my $self = shift;
	return sprintf("%u",$self->{accuracy});
}

# dumplength - return dumplength
#
sub dumplength {
	my $self = shift;
	return sprintf("%u",$self->{dumplength});
}

# clear - clear tcpdump file from memory
#
sub clear {
        my $self = shift;
        delete $self->{data};
        $self
}


1;
__END__


=head1 NAME

Net::TcpDumpLog - Read tcpdump/libpcap network packet logs. 
Perl implementation (not an interface).


=head1 SYNOPSIS

use Net::TcpDumpLog;

$log = Net::TcpDumpLog->new();
$log->read("/tmp/out01");

@Indexes = $log->indexes;

foreach $index (@Indexes) {
     ($length_orig,$length_incl,$drops,$secs,$msecs) =
                                 $log->header($index);
     $data = $log->data($index);

     # your code here
}

=head1 DESCRIPTION

This module can read the data and headers from tcpdump logs
(these use the libpcap log format).

=head1 METHODS

=over 4

=item new ()

Constructor, return a TcpDumpLog object. If your OS uses 
64-bit timestamps, supply an argument of "64".

=item read (FILENAME)

Read the tcpdump file indicated into memory.

=item indexes ()

Return an array of index numbers for the packets loaded from the
tcpdump file. The indexes start at 0.

=item maxindex ()

Return the number of the last index. More memory efficient than
indexes(). Add 1 to get the packet count. The indexes start at 0.

=item header (INDEX)

Takes an integer index number and returns the packet header. This is:
   Length of original packet,
   Length actually included in the tcpdump log,
   Number of bytes dropped in this packet,
   Packet arrival time as seconds since Jan 1st 1970,
   Microseconds

=item data (INDEX)

Takes an integer index number and returns the raw packet data.
(This is usually Ethernet/IP/TCP data).

=item version ()

Returns a string containing the libpcap log version,
major and minor number - which is expected to be "2.4".

=item linktype ()

Returns a strings containing the numeric linktype.

=item zoneoffset ()

Returns the zoneoffset for the packet log.

=item accuracy ()

Returns a the accuracy of the packet log.

=item dumplength ()

Returns the length of the packet log.

=back


=head1 INSTALLATION

   perl Makefile.PL
   make
   make test
   make install

=head1 DEPENDENCIES


ExtUtils::MakeMaker

=head1 EXAMPLES

Once you can read the raw packet data, the next step is read through the
protocol stack. An Ethernet/802.3 example is,

($ether_dest,$ether_src,$ether_type,$ether_data) =
 unpack('H12H12H4a*',$data);

Keep an eye on CPAN for Ethernet, IP and TCP modules. 

=head1 LIMITATIONS

This reads tcpdump/libpcap version 2.4 logs (the most common). There 
could be new versions in the future, at which point this module will 
need updating.

=head1 BUGS

If this module is not reading your logs correctly, try creating the
tcpdump object in 64-bit timestamp mode, eg 
"$log = Net::TcpDumpLog->new(64);". If the problem persists, try printing 
out the log version using version() and checking it is "2.4".

=head1 TODO

Future versions should include the ability to write as well as read
tcpdump logs. Also a memory efficient technique to process very large
tcpdump logs (where the log size is greater than available virtual
memory).

=head1 SEE ALSO

http://www.tcpdump.org

=head1 COPYRIGHT

Copyright (c) 2003 Brendan Gregg. All rights reserved.
This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself

=head1 AUTHORS

Brendan Gregg <brendan.gregg@tpg.com.au>
[Sydney, Australia]

=cut
