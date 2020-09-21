#!/usr/bin/perl

use Config::Tiny;

=begin comment
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ courierpop3login: (Connection|Disconnected), ip=\[[.:[:alnum:]]+\]$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ courierpop3login: LOGIN, user=[-_.@[:alnum:]]+, ip=\[[.:[:alnum:]]+\], port=\[[0-9]+\]$
^\w{3} [ :0-9]{11} [._[:alnum:]-]+ courierpop3login: (LOGOUT|TIMEOUT|DISCONNECTED), user=[-_.@[:alnum:]]+, ip=\[[.:[:alnum:]]+\], port=\[[0-9]+\], top=[0-9]+, retr=[0-9]+, rcvd=[0-9]+, sent=[0-9]+, time=[0-9]+(, stls=1)?$


Sep 19 19:28:36 malware-virtual-machine imapd: Connection, ip=[::ffff:127.0.0.1]
Sep 19 19:28:37 malware-virtual-machine imapd: LOGIN, user=mauricio, ip=[::ffff:127.0.0.1], port=[50262], protocol=IMAP
Sep 19 19:28:37 malware-virtual-machine imapd: LOGOUT, user=mauricio, ip=[::ffff:127.0.0.1], headers=184, body=0, rcvd=294, sent=1364, time=0
=cut
#use DateTime;

$archivoConf = "courier-pop_eq7.conf";
$config = Config::Tiny->read($archivoConf);
 
$logFile  = $config->{courierPop_eq7}{log};
$enable   = $config->{courierPop}{enable};
$log 	  = $config->{courierPop}{log};
$filter   = $config->{courierPop}{filter};
$attempts = $config->{courierPop}{attempts};
$time 	  = $config->{courierPop}{time};

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

sub epoch{
	$fecha = shift;
	@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	$fecha =~ m#([A-Z][a-z]+) (\d+) (\d+):(\d+):(\d+)#;
	$index = first_index { $_ eq $1 } @months;
	#$sec,$min,$hour,$mday,$mon,$year
	return timegm($5,$4,$3,$2,$index,2020);
}


#Apertura de archivo de logs

$archivoLogs = "/var/log/mail.log"; #También puede ser /var/log/mail.log.1 , no de qué dependa, al inicio fue en .1, cuando use telnet ya fue el mail.log :S
#=begin comment
open (LOGF, "<", $archivoLogs) or die $!;

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
	#Empieza la comparación de los logs
	if ($_ =~ /^\w{3} [ :0-9]{11} [._[:alnum:]-]+ imapd: (Connection|Disconnected), ip=\[[.:[:alnum:]]+\]$/){
		print $_;
	}
}

close(LOGF);
#=cut
=begin comment
use Socket;
my $port = shift or die "no port specified";
my $proto = getprotobyname('tcp');
my $sysname = `uname -n`;

# create socket
socket(SERVER, PF_INET, SOCK_STREAM, $proto) or die "socket: $!";
setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, 1) or die "setsock: $!";

# local port
my $paddr = sockaddr_in($port, INADDR_ANY);

# bind and listen
bind(SERVER, $paddr) or die "bind: $!";
listen(SERVER, SOMAXCONN) or die "listen: $!";
print "SERVER started on port $port ";

# accepting a connection
my $client_addr;
while ($client_addr = accept(CLIENT, SERVER))
{
# who is connecting?
my ($client_port, $client_ip) = sockaddr_in($client_addr);
my $client_ipnum = inet_ntoa($client_ip);
print "connection from: $client_ipnum";

# print message, close connection
print CLIENT "------------------------------\n";
print CLIENT "You have connected to $sysname";
print CLIENT "------------------------------\n";
#close CLIENT;
}
close CLIENT;
=cut