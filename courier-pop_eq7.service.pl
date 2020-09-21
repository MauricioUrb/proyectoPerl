#!/usr/bin/perl

use Daemon::Control;
use Time::Local;
use Config::Tiny;

$path = `pwd`;
chomp($path);

$archivoConf = "courier-pop_eq7.conf";
$config = Config::Tiny->read($archivoConf);
$logFile  = $config->{courierPop_eq7}{log};
print $logFile;
open (REGLOG, ">>", $logFile) or die $!;
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
$fechaGlobal = ($year+1900)." ".($mon+1)." ".$mday." ".$hour.":".$min.":".$sec;

if($ARGV[0] eq "start"){
    print REGLOG "$fechaGlobal Se ha iniciado el servicio\n";
}
elsif($ARGV[0] eq "stop"){
    print REGLOG "$fechaGlobal Se ha detenido el servicio\n";
}

close REGLOG;

exit Daemon::Control->new(
    name        => "Courier-pop",
    lsb_start   => "$syslog $remote_fs",
    lsb_stop    => "$syslog",
    lsb_sdesc   => "Courier-pop",
    lsb_desc    => "courier-pop_eq7.pl daemon",
    path        => $path."/daemon.pl",
    program     => "$path/courier-pop_eq7.pl",
    pid_file    => "/tmp/mydaemon.pid",
    stderr_file => "/tmp/mydaemon.out",
    stdout_file => "/tmp/mydaemon.out",
    fork        => 2,
)->run;