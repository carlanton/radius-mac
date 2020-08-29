#!/usr/bin/perl

use Getopt::Long;
use POSIX;

use lib '/opt/vyatta/share/perl5';
use Vyatta::Config;

use warnings;
use strict;

my $unit = 'radius-mac.service';
my $config_file = '/etc/radius-mac.ini';

sub disable_service {
    system("/bin/systemctl disable $unit");
    system("/bin/systemctl stop $unit");
    unlink($config_file);
}

sub update_service {
    my $config = new Vyatta::Config;

    $config->setLevel('service radius-mac');

    my $address = $config->returnValue('address');
    my $port = $config->returnValue('port');
    my $default_vid = $config->returnValue("default-vlan-id");
    my $secret = $config->returnValue('secret');

    (my $cfg = qq{; radius-mac
        ; generated config - do not edit
        [server]
        address = $address
        port = $port
        secret = $secret
        default_vlan = $default_vid
    }) =~ s/^ *//mg;

    $config->setLevel('service radius-mac client');
    my @clients = $config->listNodes();
    foreach my $client (@clients) {
      my $vlan = $config->returnValue("$client vlan-id");
      my $description = $config->returnValue("$client description");
      $cfg .= "\n[$client]\n";
      $cfg .= "description = $description\n";
      $cfg .= "vlan = $vlan\n";
    }
    

    if (-e $config_file) {
       my $document = do {
         local $/ = undef;
         open my $fh, "<", $config_file or die "could not open $config_file: $!";
         <$fh>;
       };
       if ($document eq $cfg) {
           return;
       }
    }

    open(my $fh, '>', $config_file) or die "Could not open file '$config_file' $!";
    chmod(0600, $fh);
    print $fh $cfg;
    close $fh;

    system("/bin/systemctl enable $unit");
    system("/bin/systemctl restart $unit");
}

my ($update, $delete);

GetOptions(
    "update!" => \$update,
    "delete!" => \$delete,
);

if ($update) {
    update_service();
    exit 0;
}

if ($delete) {
    disable_service();
    exit 0;
}

exit 1;
