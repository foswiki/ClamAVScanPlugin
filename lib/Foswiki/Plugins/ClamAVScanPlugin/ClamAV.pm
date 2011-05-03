
package Foswiki::Plugins::ClamAVScanPlugin::ClamAV;
use strict;
use warnings;
use File::Find qw(find);
use IO::Socket;

sub new {
    my $this = shift;
    my (%options) = @_;
    $options{port} ||= '/tmp/clamd';
    return bless \%options, $this;
}

=begin TML
---++ Version

Return the clamd and database version information.

=cut

sub version {
    my ($this) = @_;
    my $conn     = $this->_get_connection || return;
    my $results  = '';
    my $response = '';

    $this->_send( $conn, "zVERSION\x00" );

    for my $result ( $conn->getline ) {
        chop($result);
        $response .= $result . "\n";
    }

    $conn->close;

    return $response;
}

=begin TML
---++ Ping

Pings the clamd to check it is alive. Returns true if it is alive, false if it is dead. 

=cut

sub ping {
    my ($this) = @_;
    my $conn = $this->_get_connection || return;

    $this->_send( $conn, "zPING\x00" );
    chop( my $response = $conn->getline );

    # Run out the buffer?
    1 while (<$conn>);

    $conn->close;

    return (
        $response eq "PONG"
        ? 1
        : $this->errstr("Unknown reponse from ClamAV service: $response")
    );
}

=begin TML
---++ scan($dir_or_file)

Scan a directory or a file. Note that the resource must be readable by the user the ClamdAV clamd service is running as.

Returns a hash of C<< filename => virusname >> mappings.

On error nothing is returned and the errstr() error handler is set. If no virus is found nothing will be returned and the errstr() error handle won't be set.

=cut

sub scan {
    my $this = shift;
    my @results;

    if ( $this->{find_all} ) {
        @results = $this->_scan( 'SCAN', @_ );
    }
    else {
        @results = $this->_scan_shallow( 'SCAN', @_ );
    }

    my %f;
    for (@results) {
        $f{ $_->[0] } = $_->[1];
    }

    if (%f) {
        return %f;
    }
    else {
        return;
    }
}

=begin TML

---++ scan_stream($stream);

Preform a scan on a stream of data for viruses with the ClamAV clamd module.

Returns a list of two arguments: the first being the response which will be 'OK' or 'FOUND' the second being the virus found - if a virus is found.

On failure it sets the errstr() error handler.

=cut

sub scan_stream {
    my ( $this, $st ) = @_;

    $this->errstr();

    my $conn = $this->_get_connection || die "no connection";
    $this->_send( $conn, "zINSTREAM\x00" );

    my @return;

    # transfer 512KB blocks
    my $transfer;
    while ( my $r = sysread( $st, $transfer, 0x80000 ) ) {
        if ( !defined $r ) {
            next if ( $! == Errno::EINTR );
            die "system read error: $!\n";
        }
        print STDERR "READ $r bytes\n";

        my $out = pack( 'N', ($r) ) . $transfer;
        $this->_send( $conn, $out );
    }
    $this->_send( $conn, pack( 'N', (0) ) );

    chomp( my $r = $conn->getline );
    $conn->close;

    if ( $r =~ m/stream: (.+) FOUND/i ) {
        return ( 'FOUND', $1 );
    }
    else {
        return ('OK');
    }
}

=begin TML

---++ scan_string($text);

Preform a scan on a string using the ClamAV clamd module.

Returns a list of two arguments: the first being the response which will be 'OK' or 'FOUND' the second being the virus found - if a virus is found.

On failure it sets the errstr() error handler.

=cut

sub scan_string {
    my ( $this, $st ) = @_;

    $this->errstr();

    my $conn = $this->_get_connection || die "no connection";
    $this->_send( $conn, "zINSTREAM\x00" );

    my @return;

    my $out = pack( 'N', ( length $st ) ) . $st;
    $this->_send( $conn, $out );

    $this->_send( $conn, pack( 'N', (0) ) );  # Mark end of stream.

    chomp( my $r = $conn->getline );
    $conn->close;

    if ( $r =~ m/stream: (.+) FOUND/i ) {
        return ( 'FOUND', $1 );
    }
    else {
        return ('OK');
    }
}

=begin TML

---++ reload();

Cause ClamAV clamd service to reload its virus database.

=cut

sub reload {
    my $this = shift;
    my $conn = $this->_get_connection || return;
    $this->_send( $conn, "zRELOAD\x00" );

    my $response = $conn->getline;
    1 while (<$conn>);
    $conn->close;
    return 1;
}

=begin TML

---++ ClassMethod errstr($err) -> $string;

If called with a value, sets the error string and returns false, otherwise returns the error string.

=cut

sub errstr {
    my ( $this, $err ) = @_;
    if ($err) {
        $this->{'.errstr'} = $err;
        return 0;
        }
    else {
        return $this->{'.errstr'};
    }
}

=begin TML

---++ ClassMethod _scan();

Internal function to scan a file or iles.

=cut
sub _scan {
    my $this    = shift;
    my $cmd     = shift;
    my $options = {};

    if ( ref( $_[-1] ) eq 'HASH' ) {
        $options = pop(@_);
    }

    # Files
    my @files = grep { -f $_ } @_;

    # Directories
    for my $dir (@_) {
        next unless -d $dir;
        find(
            sub {
                if ( -f $File::Find::name ) {
                    push @files, $File::Find::name;
                }
            },
            $dir
        );
    }

    if ( !@files ) {
        return $this->errstr(
            "scan() requires that you specify a directory or file to scan");
    }

    my @results;

    for (@files) {
        push @results, $this->_scan_shallow( $cmd, $_, $options );
    }

    return @results;
}

=begin TML

---++ ClassMethod _scan_shallow();

Internal function to scan files, stopping on the first occurrence. 

=cut
sub _scan_shallow {

    # same as _scan, but stops at first virus
    my $this    = shift;
    my $cmd     = shift;
    my $options = {};

    if ( ref( $_[-1] ) eq 'HASH' ) {
        $options = pop(@_);
    }

    my @dirs = @_;
    my @results;

    for my $file (@dirs) {
        my $conn = $this->_get_connection || return;
        $this->_send( $conn, "$cmd $file\n" );

        for my $result ( $conn->getline ) {
            chomp($result);

            my @result = split( /\s/, $result );

            chomp( my $code = pop @result );
            if ( $code !~ /^(?:ERROR|FOUND|OK)$/ ) {
                $conn->close;

                return $this->errstr(
                    "Unknown response code from ClamAV service: $code - "
                      . join( " ", @result ) );
            }

            my $virus = pop @result;
            my $file = join( " ", @result );
            $file =~ s/:$//g;

            if ( $code eq 'ERROR' ) {
                $conn->close;

                return $this->errstr(
                    "Error while processing file: $file $virus");
            }
            elsif ( $code eq 'FOUND' ) {
                push @results, [ $file, $virus, $code ];
            }
        }

        $conn->close;
    }

    return @results;
}

sub _send {
    my ( $this, $fh, $data ) = @_;
    return syswrite $fh, $data, length($data);
}

sub _get_connection {
    my ($this) = @_;
    if ( $this->{port} =~ /\D/ ) {
        return $this->_get_unix_connection;
    }
    else {
        return $this->_get_tcp_connection;
    }
}

sub _get_tcp_connection {
    my ( $this, $port ) = @_;
    $port ||= $this->{port};

    return IO::Socket::INET->new(
        PeerAddr => 'localhost',
        PeerPort => $port,
        Proto    => 'tcp',
        Type     => SOCK_STREAM,
        Timeout  => 10
    ) || $this->errstr("Cannot connect to 'localhost:$port': $@");
}

sub _get_unix_connection {
    my ($this) = @_;
    return IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => $this->{port}
      )
      || $this->errstr("Cannot connect to unix socket '$this->{port}': $@");
}

1;
__END__

=head1 AUTHOR

George Clark,  derived from previous work by:

Colin Faber <cfaber@fpsn.net> All Rights Reserved.

Originally based on the Clamd module authored by Matt Sergeant.

=head1 LICENSE

This is free software and may be used and distribute under terms of perl itself.

=cut
