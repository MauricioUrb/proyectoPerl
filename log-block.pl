use Proc::Daemon;
 
$daemon = Proc::Daemon->new(
    work_dir => '/etc/log-block',
);
if($ARGV[$#ARGV] eq "start"){
    $Kid_1_PID = $daemon->Init( { 
                    exec_command => 'perl /etc/log-block/proyecto.pl start',
                 } );
    $pid = $daemon->Status();
}
if($ARGV[$#ARGV] eq "stop"){
    $stopped = $daemon->Kill_Daemon();
}

