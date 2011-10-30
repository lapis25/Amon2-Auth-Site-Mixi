# usage:
# $ MIXI_CLIENT_ID=... MIXI_CLIENT_SECRET=... MIXI_REDIRECT_URI=... plackup eg/app.psgi
use strict;
use warnings;
use utf8;
use File::Spec;
use File::Basename;
use lib File::Spec->catdir(dirname(__FILE__), '../lib');
use Plack::Builder;
use Amon2::Lite;

sub config {
    +{
        Auth => {
            Mixi => {
                client_id     => $ENV{MIXI_CLIENT_ID},
                client_secret => $ENV{MIXI_CLIENT_SECRET},
                redirect_uri  => $ENV{MIXI_REDIRECT_URI},
            }
        }
    }
}

get '/' => sub {
    my $c = shift;
    my $auth = $c->session->get('auth_mixi') || {};
    return $c->render('index.tt', { user => $auth->{user} });
};

get '/logout' => sub {
    my $c = shift;
    $c->session->expire;
    $c->redirect('/');
};

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

builder {
    enable 'Plack::Middleware::Session';
    __PACKAGE__->to_app();
};

__DATA__

@@ index.tt
<!doctype html>
<html>
<head>
    <met charst="utf-8">
    <title>MyApp</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Amon2::Auth::Site::Mixi</h1>
    [% IF user %]
    <p>
      <a href="[% user.profileUrl %]">
        <img src="[% user.thumbnailUrl %]" width="75" />
        [% user.displayName %]
      </a>
    </p>

    <p><a href="/logout">Logout</a></p>
    [% ELSE %]
    <a href="/auth/mixi/authenticate">Login</a>
    [% END %]
</body>
</html>
