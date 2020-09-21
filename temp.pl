#!/usr/bin/perl

use Config::Tiny;
use Time::Local;
use List::MoreUtils qw(first_index);
use Data::Dumper;
use Try::Tiny;

$archivoConf = "courier-pop_eq7.conf";
$config = Config::Tiny->read($archivoConf);
 
$logFile  = $config->{courierPop_eq7}{log};
$enable   = $config->{courierPop}{enable};
$log 	  = $config->{courierPop}{log};
$filter   = $config->{courierPop}{filter};
$attempts = $config->{courierPop}{attempts};
$time 	  = $config->{courierPop}{time};

@registros = ("Jan 06 09:18:17 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:127.0.0.1], port=[50262], protocol=IMAP",
"Jul 10 10:08:22 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:127.0.0.1], port=[50262], protocol=IMAP",
"Jul 10 10:08:22 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:127.0.0.1], port=[50262], protocol=IMAP",
"Jul 10 10:08:32 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:127.0.0.1], port=[50262], protocol=IMAP",
"Jul 10 10:08:42 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:127.0.0.1], port=[50262], protocol=IMAP",
"Aug 01 20:18:06 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:168.224.5.1], port=[50262], protocol=IMAP",
"Aug 01 20:18:16 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:168.224.5.1], port=[50262], protocol=IMAP",
"Aug 01 20:18:26 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:168.224.5.1], port=[50262], protocol=IMAP",
"Aug 01 20:18:36 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:168.224.5.1], port=[50262], protocol=IMAP",
"Sep 19 19:28:37 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:192.168.0.1], port=[50262], protocol=IMAP",
"Sep 19 19:28:47 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:192.168.0.1], port=[50262], protocol=IMAP",
);

foreach $registro (@registros){
	$registro =~ m#([A-Z][a-z]+ \d+ \d+:\d+:\d+).*\[(.*:\d+\.\d+\.\d+\.\d+)\]#;
	#$1 -> Fecha
	#$2 -> IP
	unless(exists($hosts{"$2"})){
		$hosts{"$2"} = epoch($1);
	}else{
		$valor = $hosts{"$2"};
		$hosts{"$2"} = "$valor ".epoch($1);
	}
}

foreach $key (keys %hosts){
	@fechas = split " ", $hosts{$key};
	$size = scalar @fechas;
	if($size > 1){
		foreach $fecha (@fechas){
			if($fecha-$time <= $fechaAnterior){
				$contadorAttemps ++;
				if($contadorAttemps == $attempts){
					bloqueo($key);
					print "Bloqueado $key\n";
					$contadorAttemps = 0;
					last;
				}
			}else{
				$contadorAttemps = 0;
			}
			$fechaAnterior = $fecha;
		}
	}
}

#print Dumper (\%hosts);

sub epoch{
	$fecha = shift;
	@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	$fecha =~ m#([A-Z][a-z]+) (\d+) (\d+):(\d+):(\d+)#;
	$index = first_index { $_ eq $1 } @months;
	#$sec,$min,$hour,$mday,$mon,$year
	return timegm($5,$4,$3,$2,$index,2020);
}

sub bloqueo{
	$ip = shift;
	$ip =~ m#(.*):(\d+\.\d+\.\d+\.\d+)#;
	#$1 -> IPv6
	#$2 -> IPv4
	$block_ipv6 = `sudo iptables -A INPUT -s $1 -j DROP`;
	$block_ipv4 = `sudo iptables -A INPUT -s $2 -j DROP`;
	$save = `sudo /sbin/iptables-save`;
}

=begin comment

unless(exists($hashCorreos{"$2"})){
			$hashCorreos{"$2"} = $&;
		}else{
			#Si existe, se obtiene el valor actual de la llave y se le concatena la direccion de correo
			$valor = $hashCorreos{"$2"};
			$hashCorreos{"$2"} = "$valor $&";
		}


=cut