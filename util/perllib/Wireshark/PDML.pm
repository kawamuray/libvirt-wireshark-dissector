package Wireshark::PDML;
use strict;
use warnings;
use XML::LibXML;
use XML::LibXML::XPathContext;

sub find_libvirt_packets {
    my ($class, $pdml) = @_;

    my $xpc = XML::LibXML::XPathContext->new(
        XML::LibXML->load_xml(string => $pdml)
    );
    my @nodes = $xpc->findnodes('/pdml/packet/proto[@name="libvirt"]');

    map {
        my @fields;
        for my $field ($_->findnodes('field')) {
            my %attrs = map {
                $_ => $field->findvalue("\@$_")
            } qw{ name showname size pos show value };
            push @fields, \%attrs;
        }

        +{
            size   => $_->findvalue('@size'),
            pos    => $_->findvalue('@pos'),
            fields => \@fields,
        };
    } @nodes;
}

1;
