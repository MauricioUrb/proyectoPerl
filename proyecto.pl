#!/usr/bin/perl
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
$activar = 1;
open (CONF, "<", $archivoConf) or die $!;
#leer archivo de configuracion para iniciar el servicio ???
while (<CONF>) {
	if (index($_, "# configuraciones generales del programa en Perl (courier pop)") != -1){
		$activar = 0;
	}
	if($activar){
		next;
	}
	if (index($_,"log = ") != -1){
		chop $_;
		$logFile = substr ($_,6);
	}
	if (index($_,"# configuración de servicio a monitorear") != -1){ last; }
}

#monitorear servicio
while (<CONF>) {
	if (index($_,"enable = ") != -1){
		chop $_;
		$enable = substr ($_,9);
	} elsif (index($_,"log = ") != -1){
		chop $_;
		$log = substr ($_,6);
	} elsif (index($_,"filter = ") != -1){
		chop $_;
		$filter = substr ($_,9);
	} elsif (index($_,"attempts = ") != -1){
		chop $_;
		$attempts = substr ($_,11);
	} elsif (index($_,"time = ") != -1){
		$tmp = chop $_;
		$time = substr ($_,7);
		if ($tmp ne "\n"){
			$time .= $tmp;
		}
	}
}

close(CONF);

=begin comment

print $logFile,"\n";
print $enable,"\n";
print $log,"\n";
print $filter,"\n";
print $attempts,"\n";
print $time,"\n";

=cut

#$Fleer = "Sep 19 19:28:37";
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
	return @n_Formato;
}

($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
@hoy = ($mon,$mday,$hour,$min$sec);
$omitir = 1;
$archivoLogs = "/var/log/mail.log"; #También puede ser /var/log/mail.log.1 , no de qué dependa, al inicio fue en .1, cuando use telnet ya fue el mail.log :S
#=begin comment
open (LOGF, "<", $archivoLogs) or die $!;

while (<LOGF>) {
	$Fleer = substr $_, 0, 15;
	@horaLeida = ordenFecha($Fleer);
	for($i = 0; $i < scalar @hoy; $i++){ ################ Estoy viendo esto de las comparaciones de fechas
		if ($horaLeida[$i] < $hoy[$i]){
			$omitir = 0;
			last;
		}
	}
	if ($omitir){
		next;
	}
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