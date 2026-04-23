package Plack::Middleware::BlockHeaderInjection;

# ABSTRACT: block header injections in responses

use v5.24;
use warnings;

use parent qw( Plack::Middleware );

use Plack::Util;
use Plack::Util::Accessor qw( logger status );

use experimental qw( signatures );

our $VERSION = 'v1.2.0';

=head1 SYNOPSIS

  use Plack::Builder;

  my $app = ...

  $app = builder {
    enable 'BlockHeaderInjection',
      status => 500;
    $app;
  };

=head1 DESCRIPTION

This middleware will check response headers for control characters (codes 0 through 31) (which also includes newlines that can be used for header injections).
These  are not allowed according to the L<PSGI specification|https://metacpan.org/pod/PSGI#Headers>.
If they are found, then it will the return code is set to C<500> and the offending header(s) are removed.

A common source of header injections is when parameters are passed
unchecked into a header (such as the redirection location).

An attacker can use injected headers to bypass system security, by
forging a header used for security (such as a referrer or cookie).

=attr status

The status code to return if an invalid header is found. By default,
this is C<500>.

=cut

sub call( $self, $env ) {

    # cache the logger
    $self->logger( $env->{'psgix.logger'} || sub { } )
      unless defined $self->logger;

    $self->status(500) unless $self->status;

    my $res = $self->app->($env);

    Plack::Util::response_cb(
        $res,
        sub {
            my $res = shift;

            # Sanity check headers

            my $hdrs = $res->[1];

            my $i = 0;
            while ( $i < $hdrs->@* ) {
                my $val = $hdrs->[ $i + 1 ];
                if ( $val =~ /[\N{U+00}-\N{U+1f}]/ ) {
                    my $key = $hdrs->[$i];
                    $self->log( error => "possible header injection detected in ${key}" );
                    $res->[0] = $self->status;
                    Plack::Util::header_remove( $hdrs, $key );
                }
                $i += 2;
            }

        }
    );

}

# Note: ideas borrowed from XSRFBlock

=for Pod::Coverage log

=cut

sub log( $self, $level, $msg ) {
    $self->logger->(
        {
            level   => $level,
            message => "BlockHeaderInjection: ${msg}",
        }
    );
}

=head1 SUPPORT FOR OLDER PERL VERSIONS

This module requires Perl v5.24 or later.

Future releases may only support Perl versions released in the last ten years.

=head1 SEE ALSO

L<https://en.wikipedia.org/wiki/HTTP_header_injection>

=head1 append:AUTHOR

The initial development of this module was supported by
Foxtons, Ltd L<https://www.foxtons.co.uk>.

=cut

1;
