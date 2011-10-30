package Amon2::Auth::Site::Mixi;
use strict;
use warnings;
use utf8;

use Mouse;
use LWP::UserAgent;
use URI;
use JSON;
use Amon2::Auth::Util qw(parse_content);
use Amon2::Auth;

our $VERSION = '0.01';

has client_id => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has client_secret => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has redirect_uri => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has scope => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { +[qw(r_profile)] }
);

has user_info => (
    is      => 'rw',
    isa     => 'Bool',
    default => 1,
);

has ua => (
    is => 'ro',
    isa => 'LWP::UserAgent',
    lazy => 1,
    default => sub {
        my $ua = LWP::UserAgent->new(agent => "Amon2::Auth/$Amon2::Auth::VERSION");
    },
);

has authorize_uri => (
    is      => 'ro',
    isa     => 'Str',
    default => 'https://mixi.jp/connect_authorize.pl',
);

has token_uri => (
    is      => 'ro',
    isa     => 'Str',
    default => 'https://secure.mixi-platform.com/2/token',
);

has people_api_uri => (
    is      => 'ro',
    isa     => 'Str',
    default => 'http://api.mixi-platform.com/2/people/@me/@self'
);

no Mouse;
__PACKAGE__->meta->make_immutable;

sub moniker { 'mixi' }

sub auth_uri {
    my ($self, $c, $callback_uri) = @_;

    my $uri = URI->new($self->authorize_uri);
    my %params = (
        client_id     => $self->client_id,
        response_type => 'code',
        scope         => join ' ', @{$self->scope},
    );
    $uri->query_form(%params);
    return $uri->as_string;
}

sub callback {
    my ($self, $c, $callback) = @_;
    if (my $error = $c->req->param('error')) {
        return $callback->{on_error}->($error);
    }
    my $code = $c->req->param('code');
    unless($code) {
        return $callback->{on_error}->("Cannot get a 'code' parameter");
    }

    my $uri = URI->new($self->token_uri);
    my %params = (
        grant_type    => 'authorization_code',
        client_id     => $self->client_id,
        client_secret => $self->client_secret,
        code          => $code,
        redirect_uri  => $self->redirect_uri,
    );
    $uri->query_form(%params);

    my $res = $self->ua->post($uri->as_string);
    $res->is_success or do {
        warn $res->decoded_content;
        return $callback->{on_error}->($res->decoded_content);
    };
    my $dat = decode_json($res->decoded_content);
    if (my $err = $dat->{error}) {
        return $callback->{on_error}->($err);
    }

    my $access_token  = $dat->{access_token}  or die "Cannot get a access_token";
    my $refresh_token = $dat->{refresh_token} or die "Cannot get a refresh_token";
    my @args = ($access_token, $refresh_token);

    if ($self->user_info) {
        my $people_api_uri = URI->new($self->people_api_uri);
        $people_api_uri->query_form(oauth_token => $access_token);

        my $user_res = $self->ua->get($people_api_uri->as_string);
        $user_res->is_success or return $callback->{on_error}->($user_res->status_line);
        my $user = decode_json($user_res->decoded_content);
        push @args, $user->{entry};
    }
    return $callback->{on_finished}->(@args);
}

1;
__END__

=encoding utf8

=head1 NAME

Amon2::Auth::Site::Mixi - Mixi authentication module for Amon2

=head1 SYNOPSIS

 # config
 +{
     Auth => {
         Mixi => {
             client_id     => 'Consumer Key',
             client_secret => 'Consumer Secret',
             redirect_uri  => 'Redirect URI',# must specify the URI inputted at registering the service.
         }
     }
 }
 # app
 __PACKAGE__->load_plugin('Web::Auth', {
     module   => 'Mixi',
     on_error => sub {
         my ($c, $error_message) = @_;
         die $error_message;
     },
     on_finished => sub {
         my ($c, $access_token, $refresh_token, $user) = @_;
         $c->session->set(auth_mixi => {
             user          => $user,
             access_token  => $access_token,
             refresh_token => $refresh_token,
         });
  
         $c->redirect('/');
     },
 });
 

=head1 DESCRIPTION

This is Mixi authentication module for Amon2.

=head1 ATTRIBUTES

=over 4

=item client_id (required)

Consumer key

=item client_secret (required)

Consumer secret.

=item redirect_uri (required)

Redirect URI （must specify the URI inputted at registering the service.）

=item scope (Default: [qw(r_profile)])

Scope for the authorization in array reference.

=item user_info (Default: true)

Fetch user information after authenticate?

=item ua (instance of LWP::UserAgent)

You can replace instance of L<LWP::UserAgent>.

=back

=head1 METHODS

=over 4

=item $auth->auth_uri($c:Amon2::Web, $callback_uri : Str) :Str

Get a authenticate URI.

=item $auth->callback($c:Amon2::Web, $callback:HashRef) : Plack::Response

Process the authentication callback dispatching.

=back

=head1 AUTHOR

lapis25 E<lt>lapis25@gmail.comE<gt>

=head1 SEE ALSO

L<Amon2::Auth>, mixi Developer Center L<http://developer.mixi.co.jp/en/>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
