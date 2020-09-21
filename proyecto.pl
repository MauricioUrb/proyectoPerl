#!/usr/bin/perl

use Config::Tiny;
use Time::Local;
use List::MoreUtils qw(first_index);

$archivoConf = "courier-pop_eq7.conf";
$config = Config::Tiny->read($archivoConf);
 
$logFile  = $config->{courierPop_eq7}{log};
$enable   = $config->{courierPop}{enable};
$log 	  = $config->{courierPop}{log};
$filter   = $config->{courierPop}{filter};
$attempts = $config->{courierPop}{attempts};
$time 	  = $config->{courierPop}{time};

sub analisis {
	%hosts = ();
	foreach $registro (@_){
		$registro =~ m#([A-Z][a-z]+ \d+ \d+:\d+:\d+).*\[(.*:\d+\.\d+\.\d+\.\d+)\]#;
		#$1 -> Fecha
		#$2 -> IP
		$horaReg = epoch($1) + (3600 * 5);
		if($horaReg >= (time - $time) && time >= $horaReg ){
			unless(exists($hosts{"$2"})){
				$hosts{"$2"} = epoch($1);
			}else{
				$valor = $hosts{"$2"};
				$hosts{"$2"} = "$valor ".epoch($1);
			}
		}
	}

	foreach $key (keys %hosts){
		@fechas = split " ", $hosts{$key};
		$size = scalar @fechas;
		if($size >= $attempts){
			bloqueo($key);
		}
	}
}

sub epoch{
	$fecha = shift;
	$fecha =~ m#([A-Z][a-z]+) (\d+) (\d+):(\d+):(\d+)#;
	$index = first_index { $_ eq $1 } @months;
	#$sec,$min,$hour,$mday,$mon,$year
	return timegm($5,$4,$3,$2,$index,$globalYear);
}

sub bloqueo{
	$ip = shift;
	$ip =~ m#(.*):(\d+\.\d+\.\d+\.\d+)#;
	#$1 -> IPv6
	#$2 -> IPv4
	$check_ipv6 = `sudo ip6tables -C INPUT -s $1 -j DROP`;
	$check_ipv4 = `sudo iptables -C INPUT -s $2 -j DROP`;
	unless($check_ipv6 or $check_ipv4){
		$block_ipv6 = `sudo ip6tables -A INPUT -s $1 -j DROP`;
		$save_ipv6 = `sudo /sbin/ip6tables-save`;
		$block_ipv4 = `sudo iptables -A INPUT -s $2 -j DROP`;
		$save_ipv4 = `sudo /sbin/iptables-save`;
		print "$fechaGlobal  Se bloqueó la ip: $ip\n";
		print REGLOG "$fechaGlobal  Se bloqueó la ip: $ip\n";
	}
}

################################################################################################################################

#MAIN

$archivoLogs = "/var/log/mail.log"; #También puede ser /var/log/mail.log.1 , no de qué dependa, al inicio fue en .1, cuando use telnet ya fue el mail.log :S
#$archivoLogs = $ARGV[0];
$fechaGlobal = "";
@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
$globalYear = 0;
$globalHour = 0;
$globalMin = 0;
while(1){
	unless (-d "/var/log/courier-pop_eq7"){
		system("sudo mkdir /var/log/courier-pop_eq7");
		system("sudo chmod 777 /var/log/courier-pop_eq7");
		system("sudo touch /var/log/courier-pop_eq7/courier-pop_eq7.log");
		system("sudo chmod 777 /var/log/courier-pop_eq7/courier-pop_eq7.log");
	}
	open (REGLOG, ">>", "/var/log/courier-pop_eq7/courier-pop_eq7.log") or die $!;
	#Se calcula la fecha de hoy
	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
	$fechaGlobal = ($year+1900)." ".($mon+1)." ".$mday." ".$hour.":".$min.":".$sec;
	$globalYear = $year+1900;
	$globalHour = $hour;
	$globalMin = $min;
	print REGLOG "$fechaGlobal Se ha iniciado el servicio\n";
	open (LOGF, "<", $archivoLogs) or die $!;
	# Se limpia el arreglo
	@registros = ();
	#Apertura de archivo de logs
	while (<LOGF>) {
		#Agregamos al arreglo y mandamos a la función
		chomp $_;
		if ($_ =~ /imapd: LOGIN/){
			push @registros, $_;
		}
	}
	close(LOGF);
	analisis(@registros);
	print REGLOG "$fechaGlobal Se ha pausado el servicio\n";
	close REGLOG ;
	sleep($time);
}

