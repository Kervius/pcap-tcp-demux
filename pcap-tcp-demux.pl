#!/usr/bin/env perl
use strict;
use warnings;
use Data::Dumper;
use POSIX qw(strftime);
use IO::Handle;
use Getopt::Long;

my $opt_help = 0;
my @opt_focus_port = ();
my @opt_focus_ip = ();
my $opt_exclusive = 0;
my $opt_prefix = '';
my $opt_verbose = 0;

my $current_file = '';

GetOptions (
	"only"   => \$opt_exclusive,
	"port=i" => \@opt_focus_port,
	"addr=s" => \@opt_focus_ip,
	"help"   => \$opt_help,
	"prefix=s" => \$opt_prefix,
	"verbose" => \$opt_verbose,
) or die usage();

if ($opt_help || !@ARGV) { die usage(); }

my %opt_focus_port = map { $_ => 1 } @opt_focus_port;
my %opt_focus_ip = map { $_ => 1 } @opt_focus_ip;

sub usage
{
	print "usage: pcap-tcp-demux [--opts] file.pcap\n";
	print "\t", "--prefix", "\t", "prefix for output files; input file name by default" ,"\n";
	print "\t", "--addr", "\t", "make the IP address first in the output name" ,"\n";
	print "\t", "--port", "\t", "make the TCP port first in the output name" ,"\n";
	print "\t", "--only", "\t", "ignore packets which do not match the ones specified in --addr/--port" ,"\n";
	print "\t", "--verbose", "\t", "print stats while processing" ,"\n";
	print "The tool support only the original pcap files, not NG ones.\n";
	print "TODO: do not read the whole file into the RAM.\n";
	die;
}


# http://wiki.wireshark.org/Development/LibpcapFileFormat
#	
#	typedef struct pcap_hdr_s {
#	        guint32 magic_number;   /* magic number */
#	        guint16 version_major;  /* major version number */
#	        guint16 version_minor;  /* minor version number */
#	        gint32  thiszone;       /* GMT to local correction */
#	        guint32 sigfigs;        /* accuracy of timestamps */
#	        guint32 snaplen;        /* max length of captured packets, in octets */
#	        guint32 network;        /* data link type */
#	} pcap_hdr_t;
#
#	typedef struct pcaprec_hdr_s {
#		guint32 ts_sec;         /* timestamp seconds */
#		guint32 ts_usec;        /* timestamp microseconds */
#		guint32 incl_len;       /* number of octets of packet saved in file */
#		guint32 orig_len;       /* actual length of packet */
#	} pcaprec_hdr_t;
#


use constant PCAP_MAGIC => 0xa1b2c3d4; 
use constant PCAP_CIGAM => 0xd4c3b2a1;

use constant PCAP_MAGIC_NS => 0xa1b2c34d;	# microsecond precision ts
use constant PCAP_CIGAM_NS => 0x4dc3b2a1;

use constant PCAP_HLEN => 24;
use constant PCAP_RHLEN => 16;

use constant LINKTYPE_ETHERNET => 1;		# ethernet header first
#use constant LINKTYPE_RAW => 101;		# ip header first
#use constant LINKTYPE_IPV4 => 228;
#use constant LINKTYPE_IPV6 => 229;		# no idea

use constant ETHERTYPE_IP => 0x800;

use constant IPPROTO_TCP => 6;
use constant IPPROTO_UDP => 17;


use constant TCP_FLAG_CWR => 0x80;
use constant TCP_FLAG_ECE => 0x40;
use constant TCP_FLAG_URG => 0x20;
use constant TCP_FLAG_ACK => 0x10;
use constant TCP_FLAG_PSH => 0x08;
use constant TCP_FLAG_RST => 0x04;
use constant TCP_FLAG_SYN => 0x02;
use constant TCP_FLAG_FIN => 0x01;

my %tcp_flags = (
		'CWR' => 0x80,	'ECE' => 0x40,
		'URG' => 0x20,	'ACK' => 0x10,
		'PSH' => 0x08,	'RST' => 0x04,
		'SYN' => 0x02,	'FIN' => 0x01	
	);

my @tcp_flags_o = reverse ( 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN' );


sub bswap2 { unpack("v", pack("n", $_[0])); }
sub bswap { unpack("V", pack("N", $_[0])); }
sub bswap4s { unpack("v", pack("n", $_[0])); }

my $bswap = '';
my $nsecs = '';

sub pcap_h
{
	my ($blob, $offs) = (@_);
	my $h = substr($$blob, $offs, PCAP_HLEN);
	die unless length($h) == PCAP_HLEN;
	my ( $magic, $vmaj, $vmin, $tz, $sigfigs, $snaplen, $link_type ) = unpack( 'LSSlLLL', $h ); # pack
	if ( $magic == PCAP_MAGIC || $magic == PCAP_MAGIC_NS) {
		$nsecs = ($magic == PCAP_MAGIC_NS);
		return {
			'magic' => sprintf( '0x%X', $magic ),
			'len' => PCAP_HLEN,
			'version' => ($vmaj).'.'.($vmin),
			'tz' => ($tz),
			'sigfigs' => ($sigfigs),
			'snaplen' => ($snaplen),
			'link_type' => ($link_type),
			'blob' => $h
		};
	}
	elsif ( $magic == PCAP_CIGAM || $magic == PCAP_CIGAM_NS) {
		$nsecs = ($magic == PCAP_CIGAM_NS);
		$bswap = 1;
		warn "byte swap is active.\n";
		return {
			'magic' => sprintf( '0x%X', $magic ),
			'len' => PCAP_HLEN,
			'version' => bswap2($vmaj).'.'.bswap2($vmin),
			'tz' => bswap4s($tz),
			'sigfigs' => bswap($sigfigs),
			'snaplen' => bswap($snaplen),
			'link_type' => bswap($link_type),
			'blob' => $h
		};
	}
	else {
		die "unknown magic: ", sprintf( '0x%08x', $magic );
	};

}

sub tech_date
{
	if (@_ == 1) { return strftime( '%Y%m%d-%H%M%S', localtime( $_[0] ) ); }
	if (@_ == 2) { return strftime( '%Y%m%d-%H%M%S', localtime( $_[0] ) ).sprintf( '.%06d', $_[1] ); }
	if (@_ == 3) { return strftime( '%Y%m%d-%H%M%S', localtime( $_[0] ) ).sprintf( '.%09d', $_[2] ); }
	die;
}

sub pcap_rh
{
	my ($blob, $offs) = (@_);
	my $h = substr($$blob, $offs, PCAP_RHLEN);
	die "buffer is too small: ", length($h) unless length($h) == PCAP_RHLEN;
	my ( $ts_sec, $ts_usec, $bytes, $orig_bytes ) = unpack( 'LLLL', $h ); # pack

	$ts_sec = bswap($ts_sec) if $bswap;
	$ts_usec = bswap($ts_usec) if $bswap;
	$bytes = bswap($bytes) if $bswap;
	$orig_bytes = bswap($orig_bytes) if $bswap;

	return {
		'len' => PCAP_RHLEN,
		#'blob' => $h,
		'ts_sec' => $ts_sec,
		'ts_usec' => $ts_usec,
		'bytes' => $bytes,
		'orig_bytes' => $orig_bytes,
		'ts_human' => tech_date( $ts_sec, $ts_usec )
	};
}

sub eth_h
{
	my ($blob, $offs) = @_;
	my $h = substr( $$blob, $offs, 14 );
	die unless length($h) == 14;
	my $dmac = unpack( 'H12', $h );
	my $smac = unpack( 'H12', substr($h,6,6) );
	my $eth_type = unpack( 'n', substr($h,12) ); # pack
	return {
		'len' => 14,
		#'blob' => $h,
		'src' => $smac,
		'dst' => $dmac,
		'type' => $eth_type
	};
}

sub ip_h
{
	my ($blob, $offs) = @_;
	my $ihl = vec( $$blob, $offs*2+0, 4 );
	my $ver = vec( $$blob, $offs*2+1, 4 );
	my $h = substr( $$blob, $offs, $ihl*4 );

	my ($dummy0, $total_len, 
		$dummy1, 
		$dummy2, $proto, $chksum,
		$src,
		$dst)
	       	= unpack( 'nn'.'N'.'CCn'.'N'.'N', $h );

	return {
		'len' => $ihl*4,
		#'blob' => $h,
		'ver' => $ver,
		'total_len' => $total_len,
		'src' => join('.', unpack('C4', pack('N', $src))),
		'dst' => join('.', unpack('C4', pack('N', $dst))),
		'proto' => $proto
	};
}

sub tcp_h
{
	my ($blob, $offs) = @_;
	my ($src, $dst, $seqn, $ackn, $do, $flags, $wsiz) = unpack( 'nnNNCCn', substr( $$blob, $offs, 16 ) );
	$do = ($do & 0xf0) >> 4;
	#warn "data offset: $do ", sprintf( "(%02x)", $do ), " or ", $do*4;
	#warn "src:$src dst:$dst seqn:$seqn ackn:$ackn flags:$flags wsiz:$wsiz";
	#die;

	my @flags = grep { $flags & $tcp_flags{$_} } @tcp_flags_o;

	return {
		'len' => $do*4,
		#'blob' => substr( $$blob, $offs, $do*4 ),
		'src' => $src,
		'dst' => $dst,
		'flags' => $flags,
		'flags_human' => join(',',@flags),
		'wsiz' => $wsiz,
		'f_syn' => ($flags & TCP_FLAG_SYN),
		'f_ack' => ($flags & TCP_FLAG_ACK),
		'f_fin' => ($flags & TCP_FLAG_FIN),
		'f_rst' => ($flags & TCP_FLAG_RST),
	};
}

#sub udp_h
#{
#}


my %out_files;
my $out_count = 0;


sub tcp_packet
{
	my ($ph, $pr, $ip, $tcp, $frame) = @_;

	my $src = $ip->{src}.'.'.$tcp->{src};
	my $dst = $ip->{dst}.'.'.$tcp->{dst};
	#my $ts = $ph->{ts_human};
	my $label = '';

	# Create the ID label for the stream.
	# Sort to make sure that the packets from the same TCP stream would
	# have the same signature label.
	# Move the desired ports/addresses to the front of the signature.
	if ($opt_focus_ip{$ip->{src}} || $opt_focus_port{$tcp->{src}}) {
		$label = join('--', $src, $dst);
	}
	elsif ($opt_focus_ip{$ip->{dst}} || $opt_focus_port{$tcp->{dst}}) {
		$label = join('--', $dst, $src);
	}
	else {
		# Do nothing if not a designated port or address.
		return if $opt_exclusive;

		$label = join('--', sort( $src, $dst ) );
	}

	#warn $label, "\n" if $opt_verbose && $tcp->{flags_human} eq 'SYN';	# print a message about a new connection

	unless ($out_files{$label}) {
		my $fn = $opt_prefix || $current_file || '';
		$fn .= '--' if $fn =~ /[a-zA-Z0-9]$/;
		$fn .= $pr->{ts_human}.'--'.$label.'.pcap';
		open my $fh, '>', $fn;
		unless ($fh) {
			warn "error, can't open output file: $fn";
			open $fh, '>', '/dev/null';
		}
		else {
			warn $fn," - new file.\n" if $opt_verbose;
		}
		$out_files{$label} = $fh;
		#warn "$fh";

		# write header
		$fh->print( $ph->{blob} );
	}

	$out_count++;

	$out_files{$label}->print( $$frame ) if $out_files{$label};
}


sub process_file
{
	my ($input_file) = @_;

	open my $f, '<', $input_file or die;
	my $data;
	{local $/ = undef; $data = <$f>;}
	undef $f;
	warn $input_file, ", ", length($data), " bytes read." if $opt_verbose;

	$current_file = $input_file;
	$current_file =~ s{\.pcap$}{}i;

	my $last_time = time;
	my $frame_count = 0;
	
	$out_count = 0;

	my $offs = 0;

	my $pcap_header = pcap_h( \$data, $offs );
	#warn 'pcap header:', Dumper( $pcap_header );
	$offs += $pcap_header->{len};

	die "unsupported link type: ", $pcap_header->{link_type} unless $pcap_header->{link_type} == LINKTYPE_ETHERNET;

	while ($offs < length($data)) {
		my $pr = pcap_rh( \$data, $offs );
		#warn 'pcap record: ', Dumper( $pr );
		#warn 'pcap record, ', $pr->{bytes}, " bytes\n";

		# make a full copy of the frame
		my $frame_start_offs = $offs;
		my $frame = substr( $data, $offs, $pr->{len} + $pr->{bytes} );
		my $fo = $pr->{len};

		$offs += $pr->{len};

		eval { for ('once') {
			my $eth = eth_h( \$frame, $fo );
			#warn 'ethernet: ', Dumper( $eth );
			next unless $eth;
			$fo += $eth->{len};

			if ($eth->{type} == ETHERTYPE_IP) {
				my $ip = ip_h( \$frame, $fo );
				next unless $ip;
				#warn 'ip: ', Dumper( $ip );
				$fo += $ip->{len};

				if ($ip->{proto} == IPPROTO_TCP) {
					my $tcp = tcp_h( \$frame, $fo );
					next unless $tcp;
					#warn 'tcp: ', Dumper( $tcp );
					$fo += $tcp->{len};

					tcp_packet( $pcap_header, $pr, $ip, $tcp, \$frame );
				}
				else {
					warn "unsupported ipproto: ", $ip->{type};
				}
			}
			else {
				warn "unsupported ethertype: ", $eth->{type};
			}
		}};
		warn "$@" if $@;

		$offs = $frame_start_offs + $pr->{bytes} + $pr->{len};

		$frame_count++;
		if ($opt_verbose) {
			if ((my $new_time = time) != $last_time) {
				$last_time = $new_time;
				warn "$frame_count frames processed...\n";
			}
		}
	}

	if ($opt_verbose) {
		warn "$frame_count frames total; ", $out_count ," frames written into ", scalar(keys %out_files) ," files.\n";
	}

	$out_files{$_}->close() for keys %out_files;
	%out_files = ();

}

process_file($_) for @ARGV;
