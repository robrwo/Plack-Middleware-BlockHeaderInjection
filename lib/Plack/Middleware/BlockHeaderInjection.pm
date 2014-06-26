package Plack::Middleware::BlockHeaderInjection;

use strict;
use warnings;

use parent qw( Plack::Middleware );

use Plack::Util;
use Plack::Util::Accessor qw( logger status );

use version 0.77; our $VERSION = version->declare('v0.1.0');

sub call {
    my ( $self, $env ) = @_;

    # cache the logger
    $self->logger($env->{'psgix.logger'} || sub { })
        unless defined $self->logger;

    $self->status(500) unless $self->status;

    my $res = $self->app->($env);

    Plack::Util::response_cb(
        $res,
        sub {
            my $res = shift;

            # Sanity check headers

            my $headers = $res->[1];
            while (my ($key, $val) = each %{$headers}) {
                if ($val =~ /[\n\r]/) {
                    $self->log( error => 'possible header injection detected' );
                    $res->[0] = $self->status;
                    Plack::Util::header_remove($headers, $key);
                    return $res;
                }
            }

        }
    );
}

# Note: ideas borrowed from XSRFBlock

sub log {
    my ($self, $level, $msg) = @_;
    $self->logger->({
        level   => $level,
        message => "Security::Simple: ${msg}",
    });
}



1;
