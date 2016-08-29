# See bottom of file for license and copyright information

package Foswiki::Plugins::ClamAVScanPlugin::ClamAV;
use strict;
use warnings;
use File::Find qw(find);
use IO::Socket;
use Foswiki::OopsException;
use Encode;

use constant TRACE => 0;

#use Socket::PassAccessRights;   # included by "eval" in scan subroutine.  If not available, scanning might fail due to file access rights

=begin TML
---++ ClassMethod new()

Create a new ClamAV Connection object.

=cut

sub new {
    my $this = shift;
    my (%options) = @_;
    $options{port} ||= '/tmp/clamd';
    return bless \%options, $this;
}

=begin TML
---++ ObjectMethod Version -> $string

Return the clamd and database version information.

=cut

sub version {
    my ($this) = @_;
    my $conn     = $this->_getConnection || return;
    my $results  = '';
    my $response = '';

    Foswiki::Func::writeDebug("Sending zVERSION") if TRACE;
    $this->_send( $conn, "zVERSION\x00" );

    for my $result ( $conn->getline ) {
        chop($result);
        $response .= $result . "\n";
    }

    $conn->close;

    return $response;
}

=begin TML
---++ ObjectMethod Ping -> $string

Pings the clamd to check it is alive. Returns true if it is alive, false if it is dead.

=cut

sub ping {
    my ($this) = @_;
    my $conn = $this->_getConnection || return;

    Foswiki::Func::writeDebug("Sending zPING") if TRACE;
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
---++ ObjectMethod scan($dir_or_file) -> @array

Scan a directory or a file.

If Socket::PassAccessRights is available, then a file descriptor will be passed to clamd.  Otherwise the file name
is passed, and __the resource must be readable by the user the ClamdAV clamd service is running as__.

Returns an array of errors

On error nothing is returned and the errstr() error handler is set.

=cut

sub scan {
    my $this = shift;
    my @results;

    my $cmd = ( eval "use Socket::PassAccessRights;1;" ? 'FILDES' : 'SCAN' );
    $cmd = 'SCAN' if ( $this->{forceScan} );    # test purposes

    if ( $this->{find_all} ) {
        @results = $this->_scan( $cmd, @_ );
    }
    else {
        @results = $this->_scan_shallow( $cmd, @_ );
    }

    return @results;
}

=begin TML

---++ ObjectMethod scan_stream($stream);

Preform a scan on a stream of data for viruses with the ClamAV clamd module.

Returns a list of two arguments: the first being the response which will be 'OK' or 'FOUND' the second being the virus found - if a virus is found.

On failure it sets the errstr() error handler.  Note that errors that "should not occur" were previously handled with "die"
will throw a Foswiki oops exception.   If the module is properly called, then these errors should not occur.

=cut

sub scan_stream {
    my ( $this, $st ) = @_;

    $this->errstr();

    my $conn = $this->_getConnection
      || throw Foswiki::OopsException(
        'clamavattach',
        def    => 'clamav_fail',
        params => [ "clamd connection not available  - " . $this->errstr() ]
      );
    Foswiki::Func::writeDebug("Sending zINSTREAM ...") if TRACE;
    $this->_send( $conn, "zINSTREAM\x00" );

    my @return;

    # transfer 512KB blocks
    my $transfer;
    while ( my $r = sysread( $st, $transfer, 0x80000 ) ) {
        if ( !defined $r ) {
            next if ( $! == Errno::EINTR );
            throw Foswiki::OopsException(
                'clamavattach',
                def    => 'clamav_fail',
                params => ["system read error reading the stream: $!"]
            );
        }

        my $out = pack( 'N', ($r) ) . $transfer;
        $this->_sendStream( $conn, $out );
    }
    $this->_sendStream( $conn, pack( 'N', (0) ) );
    Foswiki::Func::writeDebug(" ... transfer complete.") if TRACE;

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

---++ ObjectMethod scan_string($text);

Preform a scan on a string using the ClamAV clamd module.

Returns a list of two arguments: the first being the response which will be 'OK' or 'FOUND' the second being the virus found - if a virus is found.

On failure it sets the errstr() error handler.  Note that errors that "should not occur" were previously handled with "die"
will throw a Foswiki oops exception.   If the module is properly called, then these errors should not occur.

=cut

sub scan_string {
    my ( $this, $st ) = @_;

    $this->errstr();

    my $conn = $this->_getConnection
      || throw Foswiki::OopsException(
        'clamavattach',
        def    => 'clamav_fail',
        params => [ "clamd connection not available - " . $this->errstr() ]
      );
    Foswiki::Func::writeDebug("Sending INSTREAM: scan_string") if TRACE;
    $this->_send( $conn, "zINSTREAM\x00" );

    my @return;

    my $out = pack( 'N', ( length $st ) ) . $st;
    $this->_sendStream( $conn, $out );

    $this->_sendStream( $conn, pack( 'N', (0) ) );    # Mark end of stream.
    Foswiki::Func::writeDebug(" ... transfer complete.") if TRACE;

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

---++ ObjectMethod reload();

Cause ClamAV clamd service to reload its virus database.

=cut

sub reload {
    my $this = shift;
    my $conn = $this->_getConnection || return;
    Foswiki::Func::writeDebug("Sending zRELOAD") if TRACE;
    $this->_send( $conn, "zRELOAD\x00" );

    my $response = $conn->getline;
    1 while (<$conn>);
    $conn->close;
    return 1;
}

=begin TML

---++ ObjectMethod errstr($err) -> $string;

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

---++ ObjectMethod _scan();

Internal function to scan a file or directory of files.

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
        $this->errstr(
            "scan() requires that you specify a directory or file to scan");
        return undef;
    }

    my @results;

    for (@files) {
        Foswiki::Func::writeDebug("scanning $_ using $cmd") if TRACE;
        push @results, $this->_scan_shallow( $cmd, $_, $options );
    }

    return @results;
}

=begin TML

---++ ObjectMethod _scan_shallow();

Internal function to scan files, stopping on the first occurrence.

On failure it sets the errstr() error handler.  Note that errors that "should not occur" were previously handled with "die"
will throw a Foswiki oops exception.   If the module is properly called, then these errors should not occur.

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
    my $fd;

    for my $file (@dirs) {
        my $conn = $this->_getConnection || return;

        if ( $cmd eq 'SCAN' ) {
            Foswiki::Func::writeDebug("Sending zSCAN $file") if TRACE;
            $this->_send( $conn, "zSCAN $file\x00" );
        }
        else {
            Foswiki::Func::writeDebug("Sending zFILEDES for $file") if TRACE;
            $this->_send( $conn, "zFILDES\x00" );
            open( $fd, '<', $file )
              || throw Foswiki::OopsException(
                'clamavattach',
                def    => 'clamav_fail',
                params => ["failure to open $file - $!"]
              );
            Socket::PassAccessRights::sendfd( fileno($conn), fileno($fd) )
              || throw Foswiki::OopsException(
                'clamavattach',
                def => 'clamav_fail',
                params =>
                  ["failure sending file to clamd with PassAccessRights"]
              );
            close $fd;
        }

        for my $result ( $conn->getline ) {
            chomp($result);
            $result =~ s/\x00$//g;    # remove null terminator if present;
            $result = decode_utf8($result) if ( $Foswiki::UNICODE);
            my ( $fn, $msg, $code ) =
              $result =~ m/^(.*?):\s?(.*?)\s?(OK|ERROR|FOUND)$/;
            my $fname = ( $cmd eq 'SCAN' ) ? $fn : $file;
            push @results, [ $fname, $msg, $code ];
        }

        $conn->close;
    }

    return @results;
}

sub _sendStream {
    my ( $this, $fh, $data ) = @_;
    return syswrite $fh, $data, length($data);
}

# Filenames must be utf8 encoded.
sub _send {
    my ( $this, $fh, $data ) = @_;
    $data = encode_utf8($data) if ($Foswiki::UNICODE);
    return syswrite $fh, $data, length($data);
}

sub _getConnection {
    my ($this) = @_;
    if ( $this->{port} =~ /\D/ ) {
        return $this->_getUnixConnection;
    }
    else {
        return $this->_getTcpConnection;
    }
}

sub _getTcpConnection {
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

sub _getUnixConnection {
    my ($this) = @_;
    return IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => $this->{port}
    ) || $this->errstr("Cannot connect to unix socket '$this->{port}': $@");
}

1;
__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Author: George Clark - derived from previous work:

  http://search.cpan.org/dist/File-Scan-ClamAV/
  Colin Faber <cfaber@fpsn.net> All Rights Reserved.
  James Turnbull james@lovedthanlost.net

  Originally based on the Clamd module authored by Matt Sergeant.


Copyright (C) 2011-2016 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

LICENSE:

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

This is free software and may be used and distribute under terms of
perl itself.  See http://dev.perl.org/licenses/

a) the GNU General Public License as published by the Free Software Foundation;
   either version 1, or (at your option) any later version, or

b) the "Artistic License".
