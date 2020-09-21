#!/usr/bin/perl

use Config::Tiny;
use Time::Local;
use List::MoreUtils qw(first_index);

$archivoConf = "courier-pop_eq7.conf";
$config = Config::Tiny->read($archivoConf);
 
$logFile  = $config->{courierPop_eq7}{log};
$enable   = $config->{courierPop}{enable};
$log 	  = $config->{courierPop}{log};
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
	#Se bloquea la IP hasta las 23:59 UTC del dia en que se detectó 
	$block_ipv6 = `sudo ip6tables -A INPUT -s $1 -j DROP -m time --timestart $globalHour:$globalMin --timestop 23:59`;
	$save_ipv6 = `sudo /sbin/ip6tables-save`;
	$block_ipv4 = `sudo iptables -A INPUT -s $2 -j DROP -m time --timestart $globalHour:$globalMin --timestop 23:59`;
	$save_ipv4 = `sudo /sbin/iptables-save`;
	print "$fechaGlobal  Se bloqueó la ip: $ip\n";
	print REGLOG "$fechaGlobal  Se bloqueó la ip: $ip\n";
}

################################################################################################################################

#MAIN
if($enable eq "yes"){
	$fechaGlobal = "";
	@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	$globalYear = 0;
	$globalHour = 0;
	$globalMin = 0;
	while(1){
		unless (-d "/var/log/courier-pop_eq7"){
			system("sudo mkdir /var/log/courier-pop_eq7");
			system("sudo chmod 777 /var/log/courier-pop_eq7");
			system("sudo touch $logFile");
			system("sudo chmod 777 $logFile");
		}
		open (REGLOG, ">>", $logFile) or die $!;
		#Se calcula la fecha de hoy
		($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
		$fechaGlobal = ($year+1900)." ".($mon+1)." ".$mday." ".$hour.":".$min.":".$sec;
		$globalYear = $year+1900;
		$globalHour = $hour+5;
		$globalMin = $min;
		open (LOGF, "<", $log) or die $!;
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
		close REGLOG ;
		sleep($time);
	}
}else{
	print "El servicio no se encuentra habilitado en el archivo de configuración\n";
}

=head1 Documentacion courier-pop_eq7.pl

=cut

=head2 Generalidades del programa 

=over 

=item * La lectura de registros del log indicado se realiza a partir de la fecha actual menos el tiempo establecido en el archivo de configuración. 

Por ejemplo:
Si se establecio el tiempo en 60, el servicio se ejecuta cada 60 segundos y empieza a leer los registros de la hora actual menos los 60 segundos establecidos.

=item * Se ejecuta la herramienta cada n tiempo, este tiempo es establecido en el archivo de configuración.

=item * Para los cálculos con fechas estas se convierten en formato epoch ya que solamente se restan los segundos.

=item * Las direcciones IP tienen un bloqueo desde el momento que fueron detectadas hasta las 23:59 UTC.

=back

=cut

=head2 Archivo de configuración

Se utilizó el módulo Config::Tiny para realizar el parse de los valores establecidos en el archivo courier-pop_eq7.conf.

=cut

=head2 Conversión a epoch

Esta es una función auxiliar ya que se estableció que las fechas serían tratadas en este formato para poder realizar los cálculos en validaciones. 

=cut

=head2 Main

Como ya se había mencionado, la herramienta se ejecuta cada n tiempo:

=over 

=item * Se verifica si se activó el servicio en el archivo de configuración para proceder a realizar el análisis de las peticiones entrantes.

=item * Se verifica si existe la carpeta courier-pop_e7, de lo contrario la crea igual que al archivo que se ocupará como log del servicio.

=item * Se obtiene la fecha actual con ayuda de la funfión localtime().

=item * Se abre el archivo especificado donde se encuentran las bitácoras de courier-pop y se valida que sean conexiones o intentos de conexiones.

=item * Los registros que pasen la validación, se agregan a un arreglo para posteriormente ser enviado a la función analisis().

=back

=cut

=head2 Análisis

=over

=item * Se itera cada registro y se obtiene únicamente la fecha y la dirección IP.

=item * Se realiza la validación de que ese registro no debe ser mayor a la fecha actual pero sí a la fecha actual menos el tiempo establecido en el archivo de configuración.

=item * Se crea un diccionario donde cada llave es la dirección IP y los valores son las fechas donde se realizaron intentos de conexiones.

Si el diccionario no existe se crea con la llave correspondiente , de lo contrario se recupera el valor de la llave y se le anexa una nueva fecha.

=item * Al terminar la asignación de llave-valor, se itera cada llave y se realiza un split para poder hacer el conteo de los elementos. Si el número de intentos es mayor o igual al límite establecido, se llama a la función bloqueo() para que la dirección IP sea bloqueada.

=back

=cut

=head2 Bloqueo de Ip's

=back

=item * Como la dirección que es mandada a la función contiene IPv4 e IPv6 se realiza un parse de ambos protocolos.

=item * Se realiza el bloqueo de la dirección IP con ambos protocolos desde el momento en que se detectan hasta las 23:59 UTC.

=item * El bloqueo es registrado en el log establecido.

=over

=cut

=head2 La herramienta como servicio

Se utilizó el módulo Daemon::Control para poder ejecutarlo en segundo plano.

Se anexa a la bitácora la fecha de start y stop del servicio.

=cut