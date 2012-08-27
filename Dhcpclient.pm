package Net::Packet::Dhcpclient;
use strict;

use Net::PcapUtils;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::UDP;
use Net::RawIP;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
sub new {
	my $class=shift;
	my $self= {};
	my %args = @_;
	bless ($self,$class);
	exists($args{Server}) ? $self->serverid($args{Server}) : $self->{SERVER} = "0.0.0.0";
	exists($args{Requestip}) ? $self->requestip($args{Requestip}) : $self->{REQIP} = "0.0.0.0";
	exists($args{Releaseip}) ? $self->releaseip($args{Releaseip}) : $self->{RELIP} = "0.0.0.0";
	exists($args{State}) ? $self->state($args{State}) : $self->{STATE} = "INIT";
	exists($args{Interface}) ? $self->interface($args{Interface}) : $self->{INTERFACE} = "bge0";
	exists($args{Mac}) ? $self->setmac($args{Mac}) : $self->{MACADDRESS} = genmac();
	exists($args{Xid}) ? $self->setxid($args{Xid}) : $self->{XID} = transactionid();
	return $self;
	}

sub serverid{
	my $self = shift;
	if (@_)
		{ $self->{SERVER} = shift}
		die "cant set serverid $self->{SERVER}" unless $self->{SERVER}=~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ig;
		return $self->{SERVER};
	}
sub requestip{
	my $self = shift;
	if (@_)
		{$self->{REQIP} = shift}
		die "cant set requestip $self->{REQIP}" unless $self->{REQIP}=~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ig;
		return $self->{REQIP};
	}
sub releaseip
	{
	my $self = shift;
	if (@_)
		{$self->{RELIP} = shift}
		die "cant set releaseip $self->{RELIP}" unless $self->{RELIP}=~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ig;
		return $self->{RELIP};
	}
sub state{
	my $self = shift;
	if (@_)
		{$self->{STATE} = shift}
		die "cant set state $self->{STATE}" unless $self->{STATE}=~/INIT|Request|Release|Discover/ig;
		return $self->{STATE};
	}
sub interface{
	my $self = shift;
	if (@_)
		{ $self->{INTERFACE} = shift}
		  return $self->{INTERFACE};
	}
sub setmac{
	my $self= shift;
	if(@_)
		{ $self->{MACADDRESS}=shift}
		  return $self->{MACADDRESS};
	}

sub setxid{
	my $self= shift;
	if(@_)
		{ $self->{XID}=shift}
		  return $self->{XID};
	}

sub genmac{
	my $test_mac="004d";
	my $a=0;
	while($a++<4)
        {
        	$test_mac.= sprintf("%x",int rand 16);
        	$test_mac.= sprintf("%x",int rand 16);
        }
	return $test_mac;
	}

sub transactionid{
	my $xid=int(rand(0xFFFFFFFF));
	return $xid;
	}

sub createpacket{
	 my $self=shift;
       	 my $state = $self->{STATE};
	 my $p;
	 my $data;	 
		if ( $state eq 'Release')
			{
			$p= Net::DHCP::Packet->new(op => '1',
						   hlen=> '6',
						   htype=> '1',
						   hops => '0');

			$p->chaddr($self->{MACADDRESS});
			$p->xid($self->{XID});
			$p->isDhcp();
			$p->ciaddr($self->{RELIP});
			$p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 7);
			$p->addOptionValue(DHO_DHCP_SERVER_IDENTIFIER(), $self->{SERVER});
			$data=$p->serialize();
#			print $p->toString();	
			return $data;		
	 		}
		elsif ( $state eq 'Request')
			
			{
			  $p= Net::DHCP::Packet->new(op => '1',
                                                   hlen=> '6',
                                                   htype=> '1',
                                                   hops => '0');

                        $p->chaddr($self->{MACADDRESS});
                        $p->xid($self->{XID});
                        $p->isDhcp();
                        $p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 3);
                        $p->addOptionValue(DHO_DHCP_SERVER_IDENTIFIER(), $self->{SERVER});
                        $p->addOptionValue(DHO_DHCP_REQUESTED_ADDRESS(), $self->{REQIP});
			$data=$p->serialize();
#                       print $p->toString();
                        return $data;
			}	
		elsif ( $state eq 'Discover')
			{
			$p= Net::DHCP::Packet->new(op => '1',
                                                   hlen=> '6',
                                                   htype=> '1',
                                                   hops => '0');

                        $p->chaddr($self->{MACADDRESS});
                        $p->xid($self->{XID});
                        $p->isDhcp();
                        $p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 1);
                        $p->addOptionValue(DHO_DHCP_REQUESTED_ADDRESS(), $self->{REQIP});
                        $data=$p->serialize();
#                       print $p->toString();
                        return $data;
			}
		else
			{
			 $p= Net::DHCP::Packet->new(op => '1',
                                                   hlen=> '6',
                                                   htype=> '1',
                                                   hops => '0');

                        $p->chaddr($self->{MACADDRESS});
                        $p->xid($self->{XID});
                        $p->isDhcp();
                        $p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 1);
                        $p->addOptionValue(DHO_DHCP_REQUESTED_ADDRESS(), $self->{REQIP});
                        $data=$p->serialize();
#                       print $p->toString();
                        return $data;
			}
	}

sub packetsend{
	my $self= shift;
	my $data=$self->createpacket();
	my $n =Net::RawIP->new({ ip=> {
					saddr => '0.0.0.0',
					daddr => '255.255.255.255',	
					},
				  udp => {
					source => 68,
					dest => 67,
					data => $data
					}
				  });
	
	my $mac=$self->{MACADDRESS};
	my @macar = split //, $mac;
	my $i;
	my $macjoin;
	my $counter=0;
		foreach $i (@macar)
			{
			$macjoin.=$i;
			$counter++;
				if($counter%2==0)
				{
				$macjoin.=":";
				}
			}
	chop($macjoin);
	$n->ethnew($self->{INTERFACE});
	$n->ethset( source => $macjoin, dest => 'ff:ff:ff:ff:ff:ff');
	$n->ethsend;
	if ($self->{STATE} eq 'Request'|| $self->{STATE} eq 'Discover' || $self->{STATE} eq 'INIT')
		{
			if($self->{STATE} eq 'INIT')
			{
				my $reply=$self->getreply();
				$self->serverid($reply->{src_ip});
				$self->requestip($reply->{dest_ip});
				$self->state('Request');
				$self->createpacket();
				$self->printpacket();
				$self->packetsend();	
			}
		$self->getreply();
		exit();
		}
	}

sub printpacket{
	my $self=shift;
	my $data=$self->createpacket();
	my $p= Net::DHCP::Packet->new($data);
	print $p->toString();
	} 
	

sub getreply{
	my $self=shift;
	my $packetcap1= Net::PcapUtils::open( FILTER =>'udp' , DEV => $self->{INTERFACE}, SNAPLEN => 400);
	my ($packetcap)=Net::PcapUtils::next($packetcap1);
	my $ethpack=NetPacket::Ethernet->decode($packetcap);
	my $ipack=NetPacket::IP->decode($ethpack->{data});
	my $udpack=NetPacket::UDP->decode($ipack->{data});
	my $capture=Net::DHCP::Packet->new($udpack->{data});
	my $smac=sprintf ($ethpack->{src_mac});
	my $dmac=sprintf ($ethpack->{dest_mac});
	my $srcmac= sprintf("%s%s:%s%s:%s%s:%s%s:%s%s:%s%s", split//, $smac);
	my $destmac= sprintf("%s%s:%s%s:%s%s:%s%s:%s%s:%s%s", split//, $dmac);

	print ("====================BOOT REPLY========================\n");
	print "\n";
	print $ipack->{src_ip} . "=====>" . $ipack->{dest_ip} . "(id : $ipack->{id}, ttl: $ipack->{ttl})" . "\n";
	print "UDP Source: $udpack->{src_port}  ==> UDP Destination: $udpack->{dest_port} \n";
	print "UDP Length: $udpack->{len}, UDP Data Length:", length($udpack->{data})," \n";
	print "UDP Checksum: $udpack->{cksum} \n";
	print "\n";
	print "Source Mac address is : ".$srcmac."=====>";
	print "Destination Mac address is: " . $destmac."\n";
	my $ethtype=sprintf("%0.4x", $ethpack->{type});
	print "Ethertype: ". $ethtype . "\n";
	print "\n";

	print ("====================UDP PACKET========================\n");
	print $capture->toString()."\n";
	return $ipack;
	}
1;

__END__

=head1 NAME

Dhcpclient- a Dhcpclient module for Dhcp server testing

=head1 SYNOPSIS

	use Dhcpclient;
	
	my $client=Dhcpclient->(Server => '192.168.1.2',
				Requestip => '192.168.1.3',
				State => 'Request');
	$client->packetsend();


	use Dhcpclient;

	my $client=Dhcpclient->(State => 'Discover');
	$client->packetsend();

=head1 DESCRIPTION

Represents a DHCP client... as specified in RFC 2131...This module allows you to creat and manipulate
DHCP client(s) so that you can test the behaviour of your DHCP server upon client state transition. 

This module is more like Net::DHCPClientLive module


=head1 CONSTRUCTOR

This module only provides basic constructor.

=over 4

=item new()

=item new( ARG => VALUE, ARG => VALUE...)

Creates an C<Dhcpclient> object, which can send Discover,Request,Release packet.

Without argument, a default packet is created,

$client= Dhcpclient->new();


To create a fresh new client c<new()> takes arguments as a key value pairs:

FIELD		DESCRIPTION
-----		-----------

Server		DHCP server identifier default is '0.0.0.0'

Requestip	Requested ip default is '0.0.0.0'

Mac		Mac address if none supplied Mac address will be auto generated.

Xid		Transaction id if none is supplied Xid will be auto generated.

State		Discover,Request,Release..default is INIT.

Releaseip	Release ip...default is '0.0.0.0'

Interface	Interface card..default is 'bge0'


=back

=head1 METHODS

=head2 ATTRIBUT METHODS

=item serverid([STRING])

Sets DHCP server identifier.

=item  releaseip([STRING])

Sets Release ip.

=item	state([STRING])

Sets the state of the client..ie. Discover, Request or Release.

=item requestip([STRING])

Sets the requested ip.

=item setxid([INTEGER])

Sets the 32 bits Transaction Id.

=item setmac([STRING])

Sets the Mac address of the client.

=item interface([STRING])

Sets the Network Interface.

=head2 SENDING METHODS

=over 4

=item sendpacket()

Sends the packet(Request,Discover,Release)...


=head2 HELPER METHODS

=over4

=item createpacket()

Creates the packet(Request,Discover,Release)  without sending it

=item printpacket()

prints the created packet.

=item getreply()

waits for a UDP reply...DHCOFFER or ACK

=back

=head1 EXAMPLES

Here is an example of the basic transition....First the client sends a discover packet
once the server offers the packet values from the offer packet is used to send the request packet..

use Dhpclient;
use strict;

my $p=Dhcpclient->new();
$p->packetsend();



Here is another example for sending a Request packet only

my $p=Dhcpclient->new(Server => '192.168.1.1',
		      State => 'Request',
		      Interface => 'eth0',
		      Requestip => '192.168.1.3')
$p->sendpacket();

if you want to veiw the packet information

$p->printpacket();


Another example for sending a Release packet

my $p=Dhcpclient->new(Server => '192.168.1.1',
                      State => 'Release',
                      Interface => 'eth0',
                      Releaseip => '192.168.1.3')
$p->sendpacket();


=head1 REQUIRES

This module needs to use the following modules

	use Net::PcapUtils;
	use NetPacket::Ethernet;
	use NetPacket::IP;
	use NetPacket::UDP;
	use Net::RawIP;
	use Net::DHCP::Packet;
	use Net::DHCP::Constants;

=head1 AUTHOR

Drip Lockstalk, E<lt>gam3it_13@yahoo.com

=head1 COPYRIGHT AND LICENSE

Copyright 2007 by Drip Lockstalk

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
