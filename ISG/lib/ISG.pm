package ISG;

use strict;
use warnings;

use POSIX;
use Socket;
use IO::Select;
use IO::Socket::INET;
use Net::Radius::Packet;
use Net::Radius::Dictionary;
use Digest::MD5;

require Exporter;
use vars qw(@ISA @EXPORT);
@ISA = qw(Exporter);
@EXPORT = qw(prepare_netlink_socket netlink_read add_socket_for_select isg_send_event isg_parse_event isg_get_list);

use constant AF_NETLINK        => 0x10;
use constant ISG_NETLINK_MAIN  => 31;
use constant NL_HDR_LEN        => 16;
use constant NLMSG_ALIGNTO     => 4;
use constant NLMSG_DONE        => 0x3;
use constant NLM_F_MULTI       => 0x2;
use constant IN_EVENT_MSG_LEN  => 172;

use constant EVENT_LISTENER_REG  => 0x01;
use constant EVENT_SESS_APPROVE  => 0x04;
use constant EVENT_SESS_CHANGE   => 0x05;
use constant EVENT_SESS_CLEAR    => 0x09;
use constant EVENT_SESS_GETLIST  => 0x10;
use constant EVENT_SESS_GETCOUNT => 0x12;

use constant EVENT_SESS_CREATE    => 0x03;
use constant EVENT_SESS_START     => 0x06;
use constant EVENT_SESS_UPDATE    => 0x07;
use constant EVENT_SESS_STOP      => 0x08;
use constant EVENT_SESS_INFO      => 0x11;
use constant EVENT_SESS_COUNT     => 0x13;
use constant EVENT_NE_ADD_QUEUE   => 0x14;
use constant EVENT_NE_SWEEP_QUEUE => 0x15;
use constant EVENT_NE_COMMIT      => 0x16;
use constant EVENT_SERV_APPLY     => 0x17;
use constant EVENT_SDESC_ADD      => 0x18;
use constant EVENT_SDESC_SWEEP_TC => 0x19;
use constant EVENT_SERV_GETLIST   => 0x20;

use constant EVENT_KERNEL_ACK     => 0x98;
use constant EVENT_KERNEL_NACK    => 0x99;

use constant IS_APPROVED_SESSION => (1 << 0);
use constant IS_SERVICE          => (1 << 1);
use constant SERVICE_STATUS_ON   => (1 << 2);
use constant SERVICE_ONLINE      => (1 << 3);
use constant NO_ACCT             => (1 << 4);
use constant IS_DYING            => (1 << 5);
use constant SERVICE_TAGGER      => (1 << 6);

use constant FLAG_OP_SET   => 0x01;
use constant FLAG_OP_UNSET => 0x02;

use constant SERVICE_DESC_IS_DYNAMIC => (1 << 0);

sub NLMSG_ALIGN {
	my $len = shift;
	return ( (($len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) );
}

sub NLMSG_LENGTH {
	my $len = shift;
	return (($len) + NLMSG_ALIGN(NL_HDR_LEN));
}

sub NLMSG_SPACE {
	my $len = shift;
	return NLMSG_ALIGN(NLMSG_LENGTH($len));
}

sub pack_sockaddr_nl {
	my ($pid, $group_mask) = @_;
	return pack("S2iI", AF_NETLINK, 0, $pid, $group_mask);
}

sub unpack_sockaddr_nl {
	return unpack("S2iI", shift);
}

sub pack_nlmsg {
	my ($payload, $pid) = @_;

	my $payload_len = length($payload);
	return pack("IS2I2", NLMSG_SPACE(length($payload)), 0, 0, 0, $pid) . $payload;
}

sub unpack_nlmsghdr {
	return unpack("IS2I2", shift);
}

sub long2ip {
	return inet_ntoa(pack("N", shift));
}

sub ip2long {
	return unpack("N", inet_aton(shift));
}

sub ntohl {
	return unpack("L", pack("N", shift));
}

sub load_radius_dictionary {
	my $dict_dir = shift;

	my $rad_dict = new Net::Radius::Dictionary($dict_dir);
	$rad_dict->readfile($dict_dir . ".cisco");

	return $rad_dict;
}

sub format_mac {
	my ($mac, $step) = @_;
	my @pts;

	for (my $i = 0; $i <= 8 && $step; $i += $step) {
		push(@pts, substr($mac, $i, $step));
	}

	return join(".", @pts);
}

sub hex_session_id_to_llu {
	my $session_id = shift;

	if ($session_id !~ m/^[A-F0-9]{16}$/i) {
		return 0;
	}

	return pack("I", hex(substr($session_id, 8, 16))) . pack("I", hex(substr($session_id, 0, 8)));
}

sub send_coa_request {
	my ($rad_dict, $code, $coa_secret, $coa_port, $avs) = @_;
	my $rep_data;

	my $req = new Net::Radius::Packet $rad_dict;

	$req->set_code($code);
	$req->set_attr("NAS-IP-Address" => &isg_get_nas_ip());

	foreach my $av (@{$avs}) {
		foreach my $key (keys %{$av}) {
			$req->set_attr($key => $av->{$key});
		}
	}

	$req->set_identifier(1);
	$req->set_authenticator("\x0" x 16);
	$req->set_authenticator(Digest::MD5::md5($req->pack . $coa_secret));

	my $sock = IO::Socket::INET->new(
		PeerPort => $coa_port,
		PeerAddr => "localhost",
		Proto    => "udp"
		) or return 1;

	$sock->send($req->pack);

	my @ready = IO::Select->new($sock)->can_read(5);
	if (@ready) {
		if ($sock->recv($rep_data, 1500)) {
			return new Net::Radius::Packet $rad_dict, $rep_data;
		}
	}

	return 1;
}

sub init_event_fields {
	my $pars;

	$pars->{'type'} = 0;

	$pars->{'session_id'}     = "";
	$pars->{'cookie'}         = "";
	$pars->{'ipaddr'}         = 0;
	$pars->{'nat_ipaddr'}     = 0;
	$pars->{'port_number'}    = 0;
	$pars->{'flags'}          = 0;
	$pars->{'alive_interval'} = 0;
	$pars->{'idle_timeout'}   = 0;
	$pars->{'max_duration'}   = 0;
	$pars->{'in_rate'}        = 0;
	$pars->{'in_burst'}       = 0;
	$pars->{'out_rate'}       = 0;
	$pars->{'out_burst'}      = 0;
	$pars->{'service_name'}   = "";
	$pars->{'service_flags'}  = 0;
	$pars->{'flags_op'}       = 0;

	$pars->{'nehash_pfx'}     = 0;
	$pars->{'nehash_mask'}    = 0;
	$pars->{'nehash_tc_name'} = 0;

	return $pars;
}

sub pack_event {
	my $pars = shift;

	if ($pars->{'type'} == ISG::EVENT_SDESC_ADD) {

		return pack("I a32 a32 C a23",
			$pars->{'type'},
			$pars->{'nehash_tc_name'},
			$pars->{'service_name'},
			$pars->{'service_flags'}
			);

	} elsif ($pars->{'type'} == ISG::EVENT_NE_ADD_QUEUE) {

		return pack("I N2 a32 a48",
			$pars->{'type'},
			$pars->{'nehash_pfx'},
			$pars->{'nehash_mask'},
			$pars->{'nehash_tc_name'}
			);

	} else {

		return pack("I a8 a32 N2 H12 V I8 a32 C",
			$pars->{'type'},
			$pars->{'session_id'},
			$pars->{'cookie'},
			$pars->{'ipaddr'},
			$pars->{'nat_ipaddr'},
			0, # MAC-Address is read-only
			$pars->{'flags'},
			$pars->{'port_number'},
			$pars->{'alive_interval'},
			$pars->{'idle_timeout'},
			$pars->{'max_duration'},
			$pars->{'in_rate'},
			$pars->{'in_burst'},
			$pars->{'out_rate'},
			$pars->{'out_burst'},
			$pars->{'service_name'},
			$pars->{'flags_op'}
			);
	}
}

sub unpack_event {
	my $pars;

	my $trash;
	my ($in_packets_lo, $in_packets_hi, $out_packets_lo, $out_packets_hi);
	my ($in_bytes_lo, $in_bytes_hi, $out_bytes_lo, $out_bytes_hi);
	my ($session_id_hi, $session_id_lo);
	my ($p_session_id_hi, $p_session_id_lo);

	(
		$pars->{'type'},
		$session_id_hi,
		$session_id_lo,
		$pars->{'cookie'},
		$pars->{'ipaddr'},
		$pars->{'nat_ipaddr'},
		$pars->{'macaddr'},
		$pars->{'flags'},
		$pars->{'port_number'},
		$pars->{'alive_interval'},
		$pars->{'idle_timeout'},
		$pars->{'max_duration'},
		$pars->{'in_rate'},
		$pars->{'in_burst'},
		$pars->{'out_rate'},
		$pars->{'out_burst'},
		$pars->{'duration'},
		$trash, # Padding
		$in_packets_hi,
		$in_packets_lo,
		$in_bytes_hi,
		$in_bytes_lo,
		$out_packets_hi,
		$out_packets_lo,
		$out_bytes_hi,
		$out_bytes_lo,
		$p_session_id_hi,
		$p_session_id_lo,
		$pars->{'service_name'}
	) = unpack("I I2 a32 N2 H12 V I8 I i I10 a32", shift);

	$pars->{'service_name'} =~ s/\000//g;
	if (!length($pars->{'service_name'})) {
		undef($pars->{'service_name'});
	}

	$pars->{'cookie'} =~ s/\000//g;
	if (!length($pars->{'cookie'})) {
		undef($pars->{'cookie'});
	}

	if ($pars->{'macaddr'} eq "000000000000") {
		undef($pars->{'macaddr'});
	}

	$pars->{'session_id'} = sprintf("%08X%08X", $session_id_lo, $session_id_hi);

	if ($p_session_id_lo || $p_session_id_hi) {
		$pars->{'parent_session_id'} = sprintf("%08X%08X", $p_session_id_lo, $p_session_id_hi);
	}

	$pars->{'in_packets'} = ($in_packets_lo * 2**32) + $in_packets_hi;
	$pars->{'out_packets'} = ($out_packets_lo * 2**32) + $out_packets_hi;
	$pars->{'in_bytes'} = ($in_bytes_lo * 2**32) + $in_bytes_hi;
	$pars->{'out_bytes'} = ($out_bytes_lo * 2**32) + $out_bytes_hi;

	return $pars;
}

sub prepare_netlink_socket {
	my $sk;

	if (!socket($sk, AF_NETLINK, SOCK_RAW, ISG_NETLINK_MAIN)) {
		goto err;
	}

	if (!bind($sk, pack_sockaddr_nl(0, 0))) {
		goto err;
	}

	setsockopt($sk, SOL_SOCKET, SO_RCVBUF, pack("L", 2097152));

	return $sk;
err:
	return -1;
}

sub netlink_read {
	my ($sk, $buffer, $size, $timeout) = @_;
	my $nread;

	eval {
		local $SIG{ALRM} = sub { die "alarm\n" };
		alarm($timeout);
		$nread = sysread($sk, $$buffer, $size);
		alarm(0);
	};

	if ($@) {
		return undef;
	} else {
		return $nread;
	}
}

sub isg_send_event {
	my ($sk, $pars, $reply) = @_;

	my $data;
	my $ev = init_event_fields();

	foreach my $key (keys %{$pars}) {
		if (defined($pars->{"$key"})) {
			$ev->{"$key"} = $pars->{"$key"};
		}
	}

	if (!send($sk, pack_nlmsg(pack_event($ev), $$), 0, pack_sockaddr_nl(0, 0))) {
		return -1;
	}

	if (defined($reply)) {
		if (!netlink_read($sk, \$data, 16384, 10)) {
			return -1;
		} else {
			$ev = isg_parse_event($data);
			foreach my $key (keys %{$ev}) {
				$reply->{"$key"} = $ev->{"$key"};
			}
		}
	}

	return 1;
}

sub isg_parse_event {
	my $data = shift;

	my @nlhdr = unpack_nlmsghdr($data);
	my $pars = unpack_event(substr($data, NL_HDR_LEN));

	$pars->{'nlhdr_len'}   = $nlhdr[0];
	$pars->{'nlhdr_type'}  = $nlhdr[1];
	$pars->{'nlhdr_flags'} = $nlhdr[2];
	$pars->{'nlhdr_seq'}   = $nlhdr[3];
	$pars->{'nlhdr_pid'}   = $nlhdr[4];

	return $pars;
}

sub isg_get_nas_ip {
	my @uname = uname();
	my $name = gethostbyname($uname[1]);

	if ($name) {
		return inet_ntoa($name);
	}

	return;
}

sub dumper {
	my $var = shift;

	use Data::Dumper;
	print STDERR Dumper($var);
}

sub isg_get_list {
	my ($sk, $ev) = @_;
	my @ret;

	if (isg_send_event($sk, $ev) < 0) {
		goto err;
	}

	my $tot_msg_sz = NL_HDR_LEN + IN_EVENT_MSG_LEN;
	my $stop = 0; my $data;

	while (!$stop) {
		if (!(my $read_b = netlink_read($sk, \$data, 16384, 10))) {
			print STDERR "Recv from kernel: $!\n";
			goto err;
		} else {
			if ($read_b < $tot_msg_sz) {
				print STDERR "Packet too small ($read_b bytes)\n";
				next;
			}

			if ($read_b % $tot_msg_sz) {
				print STDERR "Incorrect packet length ($read_b bytes)\n";
				next;
			}

			my $pkts_cnt = $read_b / $tot_msg_sz;

			for (my $i = 0; $i < $pkts_cnt; $i++) {
				my $offset = $i * $tot_msg_sz;

				$ev = isg_parse_event(substr($data, $offset, $tot_msg_sz));

				if ($ev->{'type'} == ISG::EVENT_SESS_INFO) {
					if ($ev->{'ipaddr'} != 0) {
						push(@ret, $ev);
					}

					if ($ev->{'nlhdr_type'} == ISG::NLMSG_DONE) {
						$stop = 1;
						last;
					}
				}
			}
		}
	}

	return \@ret;

err:
	return -1;
}

1;
