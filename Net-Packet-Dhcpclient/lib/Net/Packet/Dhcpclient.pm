package Net::DHCP::Packet::Client;
use strict;
use warnings;
use 5.8.8;

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
	exists($args{Server}) ? $self->setserverid($args{Server}) : $self->setserverid("0.0.0.0");
	exists($args{Requestip}) ? $self->setrequestip($args{Requestip}) : $self->setrequestip("0.0.0.0");
	exists($args{Releaseip}) ? $self->setreleaseip($args{Releaseip}) : $self->setreleaseip("0.0.0.0");
	exists($args{State}) ? $self->setstate($args{State}) : $self->setstate("INIT");
	exists($args{Interface}) ? $self->setinterface($args{Interface}) : $self->setinterface("em0");
	exists($args{Mac}) ? $self->setmac($args{Mac}) : $self->setmac(genmac());
	exists($args{Xid}) ? $self->setxid($args{Xid}) : $self->setxid(transactionid());
	return $self;
}

sub getserverid{
	my $self=shift;
	$self->{SERVER};
	
}


sub setserverid{
	my $self = shift;
	if (@_){ 
  	   $self->{SERVER} = shift
	}
		die "Cant set server id:$!" unless $self->{SERVER}=~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ig;
}

sub getrequestip{
	my $self=shift;
	$self->{REQIP};
}

sub setrequestip{
	my $self = shift;
	if (@_){
           $self->{REQIP} = shift
  	}
		die "Cant Set Requestip:$!" unless $self->{REQIP}=~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ig;
}

sub getreleaseip{
	my $self=shift;
	$self->{RELIP};
}

sub setreleaseip{
	my $self = shift;
	if (@_){
	   $self->{RELIP} = shift
	}
		die "Cant Set Releaseip:$!" unless $self->{RELIP}=~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ig;
}

sub getstate{
	my $self= shift;
	$self->{STATE};
}


sub setstate{
	my $self = shift;
	if (@_){
	   $self->{STATE} = shift
	}
		die "Cant Set State:$!" unless $self->{STATE}=~/INIT|Request|Release|Discover/ig;
}

sub getinterface{
	my $self=shift;
	$self->{INTERFACE};
}

sub setinterface{
	my $self = shift;
	if (@_){ 
	   $self->{INTERFACE} = shift
        }
	else{
	print "No Input Value for Interface, Using Default Value";
	}
}


sub getmac{
	my $self=shift;
	$self->{MACADDRESS};
}

sub setmac{
	my $self= shift;
	if(@_){ 
	  $self->{MACADDRESS}=shift
	}
	else{
	print "No Input Value, Using Random Generated MacAddress \n";
	}
}

sub getxid{
	my $self=shift;
	$self->{XID};
}

sub setxid{
	my $self= shift;
	if(@_){ 
	  $self->{XID}=shift
	}
	else{
	print "No Input Value, Using Default Value:\n";
	}	
}

sub genmac{
	my $test_mac="004d";
	my $a=0;
	while($a++<4){
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
       	 my $state = $self->getstate();
	 my $p;
	 my $data;	 
		if ( $state eq 'Release'){
			$p= Net::DHCP::Packet->new(op => '1',
						   hlen=> '6',
						   htype=> '1',
						   hops => '0');

			$p->chaddr($self->getmac());
			$p->xid($self->getxid());
			$p->isDhcp();
			$p->ciaddr($self->getreleaseip());
			$p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 7);
			$p->addOptionValue(DHO_DHCP_SERVER_IDENTIFIER(), $self->getserverid());
			$data=$p->serialize();
			return $data;		
	 	}
		elsif ( $state eq 'Request'){
			$p= Net::DHCP::Packet->new(op => '1',
                                                   hlen=> '6',
                                                   htype=> '1',
                                                   hops => '0');

                        $p->chaddr($self->getmac());
                        $p->xid($self->getxid());
                        $p->isDhcp();
                        $p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 3);
                        $p->addOptionValue(DHO_DHCP_SERVER_IDENTIFIER(),$self->getserverid());
                        $p->addOptionValue(DHO_DHCP_REQUESTED_ADDRESS(),$self->getrequestip());
			$data=$p->serialize();
                        return $data;
		}	
		elsif ( $state eq 'Discover'){
			$p= Net::DHCP::Packet->new(op => '1',
                                                   hlen=> '6',
                                                   htype=> '1',
                                                   hops => '0');

                        $p->chaddr($self->getmac());
                        $p->xid($self->getxid());
                        $p->isDhcp();
                        $p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 1);
                        $p->addOptionValue(DHO_DHCP_REQUESTED_ADDRESS(),$self->getrequestip());
                        $data=$p->serialize();
                        return $data;
		}
		else{
			$p= Net::DHCP::Packet->new(op => '1',
                                                   hlen=> '6',
                                                   htype=> '1',
                                                   hops => '0');

                        $p->chaddr($self->getmac());
                        $p->xid($self->getxid());
                        $p->isDhcp();
                        $p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), 1);
                        $p->addOptionValue(DHO_DHCP_REQUESTED_ADDRESS(),$self->getrequestip());
                        $data=$p->serialize();
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
	
	my $mac= $self->getmac();
	my @macar = split //, $mac;
	my $i;
	my $macjoin;
	my $counter=0;
		foreach $i (@macar){
			$macjoin.=$i;
			$counter++;
				if($counter%2==0){
				$macjoin.=":";
				}
		}
	chop($macjoin);
	$n->ethnew($self->getinterface());
	$n->ethset( source => $macjoin, dest => 'ff:ff:ff:ff:ff:ff');
	$n->ethsend;
	if ( $self->getstate() eq 'Request'|| $self->getstate() eq 'Discover' || $self->getstate() eq 'INIT'){
			if($self->getstate() eq 'INIT'){
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
	my $packetcap1= Net::PcapUtils::open( FILTER =>'udp' , DEV => getinterface(), SNAPLEN => 400);
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