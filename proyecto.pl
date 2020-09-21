#!/usr/bin/perl

use Config::Tiny;
use Time::Local;
use List::MoreUtils qw(first_index);
use Data::Dumper;

=begin comment
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ courierpop3login: (Connection|Disconnected), ip=\[[.:[:alnum:]]+\]$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ courierpop3login: LOGIN, user=[-_.@[:alnum:]]+, ip=\[[.:[:alnum:]]+\], port=\[[0-9]+\]$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ courierpop3login: (LOGOUT|TIMEOUT|DISCONNECTED), user=[-_.@[:alnum:]]+, ip=\[[.:[:alnum:]]+\], port=\[[0-9]+\], top=[0-9]+, retr=[0-9]+, rcvd=[0-9]+, sent=[0-9]+, time=[0-9]+(, stls=1)?$


Sep 19 19:28:36 malware-virtual-machine imapd: Connection, ip=[::ffff:127.0.0.1]
Sep 19 19:28:37 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:127.0.0.1], port=[50262], protocol=IMAP
Sep 19 19:28:37 malware-virtual-machine imapd: LOGOUT, user=mauricio, ip=[::ffff:127.0.0.1], headers=184, body=0, rcvd=294, sent=1364, time=0
=cut

$archivoConf = "courier-pop_eq7.conf";
$config = Config::Tiny->read($archivoConf);
 
$logFile  = $config->{courierPop_eq7}{log};
$enable   = $config->{courierPop}{enable};
$log 	  = $config->{courierPop}{log};
$filter   = $config->{courierPop}{filter};
$attempts = $config->{courierPop}{attempts};
$time 	  = $config->{courierPop}{time};

=begin comment
#Pruebas
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
=cut
$fechaGlobal = "";

sub analisis {
	%hosts = ();
	foreach $registro (@_){
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
}

sub epoch{
	$fecha = shift;
	@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	$fecha =~ m#([A-Z][a-z]+) (\d+) (\d+):(\d+):(\d+)#;
	$index = first_index { $_ eq $1 } @months;
	#$sec,$min,$hour,$mday,$mon,$year
	return timegm($5,$4,$3,$2,$index,2020);
}

sub bloqueo{
	unless (-d "/var/log/courier-pop_eq7"){
		mkdir "/var/log/courier-pop_eq7";
	}
	open (REGLOG, "+>>", "/var/log/courier-pop_eq7/courier-pop_eq7.log")
	$ip = shift;
	$ip =~ m#(.*):(\d+\.\d+\.\d+\.\d+)#;
	#$1 -> IPv6
	#$2 -> IPv4
	$block_ipv6 = `sudo iptables -A INPUT -s $1 -j DROP`;
	$block_ipv4 = `sudo iptables -A INPUT -s $2 -j DROP`;
	$save = `sudo /sbin/iptables-save`;
	print REGLOG "$fechaGlobal  Se bloqueó la ip: $ip\n";
	close(REGLOG)
}


sub ordenFecha {
	@tmpTime = split(/\s/,$_[0]);
	@tmpHora = split(/:/,$tmpTime[2]);
	if ($tmpTime[0] eq "Jan" ){
		$tmpTime[0] = 1;
	} elsif ($tmpTime[0] eq "Feb" ){
		$tmpTime[0] = 2;
	} elsif ($tmpTime[0] eq "Mar" ){
		$tmpTime[0] = 3;
	} elsif ($tmpTime[0] eq "Apr" ){
		$tmpTime[0] = 4;
	} elsif ($tmpTime[0] eq "May" ){
		$tmpTime[0] = 5;
	} elsif ($tmpTime[0] eq "Jun" ){
		$tmpTime[0] = 6;
	} elsif ($tmpTime[0] eq "Jul" ){
		$tmpTime[0] = 7;
	} elsif ($tmpTime[0] eq "Aug" ){
		$tmpTime[0] = 8;
	} elsif ($tmpTime[0] eq "Sep" ){
		$tmpTime[0] = 9;
	} elsif ($tmpTime[0] eq "Oct" ){
		$tmpTime[0] = 10;
	} elsif ($tmpTime[0] eq "Nov" ){
		$tmpTime[0] = 11;
	} elsif ($tmpTime[0] eq "Dec" ){
		$tmpTime[0] = 12;
	}
	@n_Formato = ($tmpTime[0], $tmpTime[1],$tmpHora[0],$tmpHora[1],$tmpHora[2]);
	foreach my $dato (@n_Formato) {
		if (length($dato) eq 1){
			$dato = "0" . $dato;
		}
	}
	my $fechaN = join("",@n_Formato);
	return $fechaN;
}

################################################################################################################################


$archivoLogs = "/var/log/mail.log"; #También puede ser /var/log/mail.log.1 , no de qué dependa, al inicio fue en .1, cuando use telnet ya fue el mail.log :S
#=begin comment
while(1){
	#Se calcula la fecha de hoy
	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
	@hoy = ($mon + 1,$mday,$hour,$min,$sec);
	foreach my $dato (@hoy) {
		if (length($dato) eq 1){
			$dato = "0" . $dato;
		}
	}
	$fechaHoy = join("",@hoy);
	$fechaGlobal = $mon + 1 . " " . $mday . " " . $hour . ":" . $min . ":" . $sec;
	$omitir = 1;
	sleep($time);
	open (LOGF, "<", $archivoLogs) or die $!;
	# Se limpia el arreglo
	@registros = ();
	#Apertura de archivo de logs
	while (<LOGF>) {
		#Se obtien la fecha y hora del log
		$Fleer = substr $_, 0, 15;
		$Fleer = ordenFecha($Fleer);
		if ($omitir){
			#Primero se compara fecha
			if (int($Fleer) >= int($fechaHoy)){
				#Si se llega al punto en donde las fechas ya son válidas, entonces omitimos estas comparaciones
				$omitir = 0;
			} else {
				#Mientras las fechas sean menores, seguimos omitiendo las líneas
				next;
			}
		}
		#Agregamos al arreglo y mandamos a la función
		chop $_;
		push @registros, $_;
	}
	close(LOGF);
	analisis(@registros);
}
#=cut
