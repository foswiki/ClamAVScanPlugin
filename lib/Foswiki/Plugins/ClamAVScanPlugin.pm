# See bottom of file for default license and copyright information

=begin TML

---+ package Foswiki::Plugins::ClamAVScanPlugin

This plugin will pass topic data and attachments to clamd for scanning by ClamAV


=cut

package Foswiki::Plugins::ClamAVScanPlugin;

# Always use strict to enforce variable scoping
use strict;
use warnings;

use Foswiki::Func    ();    # The plugins API
use Foswiki::Plugins ();    # For the API version
use Foswiki::Plugins::ClamAVScanPlugin::ClamAV;
use Foswiki::OopsException;
use Unicode::Normalize;
use Encode;

our $VERSION = '1.2';
our $RELEASE = '31 Aug 2016';
our $SHORTDESCRIPTION =
  'Scans attachments for viruses, malware and other threats during upload';
our $NO_PREFS_IN_TOPIC = 1;

my $clamdPort;              # Unix socket used to communicate with clamd daemon
my $cli = 0;                # Set to 1 if running in CLI environment

use constant TRACE => 0;

=begin TML

---++ StaticMethod earlyInitPlugin() -> $boolean

If running on Foswiki 1.0.x, the beforeUploadHandler doesn't exist.
Monkey patch the code to become a beforeAttachmentSaveHandler.

=cut

sub earlyInitPlugin {

    return 0 if $Foswiki::Plugins::VERSION >= 2.1;

    no strict "refs";
    *beforeAttachmentSaveHandler = \&beforeUploadHandler;
    return 0;
    use strict "refs";

}

=begin TML

---++ StaticMethod initPlugin($topic, $web, $user) -> $boolean

=cut

sub initPlugin {
    my ( $topic, $web, $user, $installWeb ) = @_;

    # check for Plugins.pm versions
    if ( $Foswiki::Plugins::VERSION < 2.0 ) {
        Foswiki::Func::writeWarning( 'Version mismatch between ',
            __PACKAGE__, ' and Plugins.pm' );
        return 0;
    }

    # Socket used to communicate with clamd daemon
    $clamdPort = $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{clamdPort}
      || '/tmp/clamd';

    # Register status tag - reports information on the clamdscan connection
    Foswiki::Func::registerTagHandler( 'CLAMAVSTATUS', \&_CLAMAVSTATUS );

    # Request clamd to reload the virus signatures
    Foswiki::Func::registerRESTHandler(
        'reload', \&_reloadSignatures,
        authenticate => 1,  # Set to 0 if handler should be useable by WikiGuest
        validate     => 1,  # Set to 0 to disable StrikeOne CSRF protection
        http_allow => 'POST', # Set to 'GET,POST' to allow use HTTP GET and POST
        description => 'Request reload ClamAV Signatures.'
    );

    # Request clamd to scan the attachments of a topic
    Foswiki::Func::registerRESTHandler(
        'scan', \&_scanAttachments,
        authenticate => 1,  # Set to 0 if handler should be useable by WikiGuest
        validate     => 1,  # Set to 0 to disable StrikeOne CSRF protection
        http_allow => 'POST', # Set to 'GET,POST' to allow use HTTP GET and POST
        description => 'Scan attachments for a requested topic'
    );

    $cli = 1 if ( Foswiki::Func::getContext()->{'command_line'} );

    # Plugin correctly initialized
    return 1;
}

=begin TML

---++ StaticMethod _CLAMAVSTATUS() -> $string

Registered Handler: Implements the CLAMAVSTATUS macro. Returns the status string.

=cut

sub _CLAMAVSTATUS {

    return
      "<div class='foswikiAlert'>Status restricted to administrators.</div>"
      unless Foswiki::Func::isAnAdmin();

    my $report = "*<nop>ClamAV Status* \n";

    $report .= "   * Connecting to socket ==$clamdPort== \n";

#return $report .= "      * <span class=\"foswikiAlert\"> %X% *FAIL* socket does not exist </span>" unless (-e $clamdPort);

    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort" );
    return $report .= "      * Error string " . $av->errstr() . "\n"
      if ( $av->errstr() );

    if ( $av->ping ) {
        $report .= "      * *PING Success* - clamd alive\n";
    }
    else {
        return $report .=
            "      * <span class=\"foswikiAlert\"> *PING failed* "
          . $av->errstr()
          . "</span> \n";
    }

    my $version = $av->version();
    chomp $version;
    $report .=
      "      * *Version:* <noautolink><code>$version</code></noautolink>\n";
    $report .=
      "      * *Mandatory Scan* - Upload denied unless !ClamAV is available.\n"
      if $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{mandatoryScan};
    $report .= "      * *Topic Scans* - Topic text scanned for threats.\n"
      if $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{scanTopics};

    return $report;
}

=begin TML

---++ StaticMethod beforeUploadHandler()

Intercepts the newly uploaded attachment before it has been stored in Foswiki.

Note, this handler will be aliased and called as a beforeAttachmentSaveHandler on
Foswiki versions older than 1.1.

Passes the stream to clamd for scanning.  Throws an exception under two conditions:
   * clamd daemon is not available, and mandatoryScan requested
   * clamd reported a threat in the file.

=cut

sub beforeUploadHandler {
    my $attrs = shift;

#   Attributes:
#   Foswiki 1.0 -  =tmpFilename= - name of a temporary file containing the attachment data
#   Foswiki 1.1 -  =stream= - an input stream that will deliver the data for the attachment

    my $meta;
    my $web;
    my $topic;

    if ( $Foswiki::Plugins::VERSION >= 2.1 ) {
        $meta  = shift;
        $topic = $meta->topic();
        $web   = $meta->web();
    }
    else {
        $topic = shift;
        $web   = shift;
    }

    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort" );

    unless ( $av->ping ) {
        return unless $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{mandatoryScan};
        throw Foswiki::OopsException(
            'clamavattach',
            def    => 'clamav_offline',
            params => [ $attrs->{attachment} ]
        );
    }

    my $ok;
    my $virus;

    if ( $Foswiki::Plugins::VERSION >= 2.1 ) {
        ( $ok, $virus ) = $av->scan_stream( $attrs->{stream} );
    }
    else {

# note:  scan returns an array of results since it can also be passed a directory.
# We are scanning an explicit file, so only the first entry matters.
        my @results = $av->scan( $attrs->{tmpFilename} );
        $virus = $results[0][1];
        $ok    = $results[0][2];
    }

    if ( $ok eq 'FOUND' ) {
        Foswiki::Func::writeWarning( "$virus detected in topic "
              . $web . '.'
              . $topic
              . " attachment $attrs->{attachment} - Upload blocked." );
        throw Foswiki::OopsException(
            'clamavattach',
            def    => 'clamav_upload',
            params => [ $attrs->{attachment}, $virus ]
        );
    }
    elsif ( $ok eq 'ERROR' ) {
        Foswiki::Func::writeWarning( "ERROR detected in scan: $virus"
              . $web . '.'
              . $topic
              . " attachment $attrs->{attachment} - Upload blocked." );
        throw Foswiki::OopsException(
            'clamavattach',
            def    => 'clamav_upload',
            params => [ $attrs->{attachment}, $virus ]
        );
    }

    return 1;
}

=begin TML

---++ StaticMethod beforeSaveHandler()

Intercepts an updated topic prior to save.

Passes the topic text to clamd for scanning.  Throws an exception:
   * scanTopics requested and clamd reported a threat in the file.

=cut

sub beforeSaveHandler {
    my ( $text, $topic, $web, $meta ) = @_;

    return unless $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{scanTopics};

    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort" );

    return unless ( $av->ping );

    my ( $ok, $virus ) = $av->scan_string($text);

    if ( $ok eq 'FOUND' ) {
        Foswiki::Func::writeWarning(
            "$virus detected in $web.$topic text during save - Save blocked.");
        throw Foswiki::OopsException( 'clamavsave', params => [$virus] );
    }

    return 1;
}

=begin TML

---++ StaticMethod  reloadSignatures($session) -> $text

Implements the rest handler "reload"

Force a reload of the antivirus signatures.
This function is only available to administrators.

=cut

sub _reloadSignatures {
    my ( $session, $subject, $verb, $response ) = @_;

    return _notAuth( $session, 'reload' ) unless Foswiki::Func::isAnAdmin();

    Foswiki::Func::writeWarning("Signature reload requested.");
    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort" );
    unless ( $av->ping ) {
        return _notActive( $session, 'reload', '', '', $av->errstr() );
    }
    $av->reload();

    return _reloadResult($session);
}

sub _readdir {

    if ($Foswiki::UNICODE) {
        map { NFC( Encode::decode_utf8($_) ) } readdir( $_[0] );
    }
    else {
        readdir( $_[0] );
    }
}

=begin TML

---++ StaticMethod scanAttachments($session) -> $text

Implements the rest handler "scan"

Performs a virus scan of all attachment for a topic.  This includes the rcs ",v"
files.  It's important to scan data stored in the prior revisions of a file.

This function is only available to administrators.

=cut

sub _scanAttachments {

    #   my ( $session, $subject, $verb, $response ) = @_;
    my $session = shift;

    return _notAuth( $session, 'scan' ) unless ( Foswiki::Func::isAnAdmin() );

    my $query = Foswiki::Func::getCgiQuery();
    my $resp  = '';

    my $web   = $session->{webName};
    my $topic = $session->{topicName};

  # Old versions use "topic" param which collides with the core topic parameter.
    my $scanTopic = $query->param('scan') || "$web.$topic";
    ( my $scanWeb, $scanTopic ) =
      Foswiki::Func::normalizeWebTopicName( undef, $scanTopic );
    $scanWeb = Foswiki::Sandbox::untaint( $scanWeb,
        \&Foswiki::Sandbox::validateWebName );
    $scanTopic = Foswiki::Sandbox::untaint( $scanTopic,
        \&Foswiki::Sandbox::validateTopicName );

    my $dir = "$Foswiki::cfg{PubDir}/$scanWeb/$scanTopic";
    my $dh;
    opendir( $dh, $dir ) || return _noAttach( $session, $scanWeb, $scanTopic );

    my $av = new Foswiki::Plugins::ClamAVScanPlugin::ClamAV(
        port      => "$clamdPort",
        find_all  => 1,
        forceScan => $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{forceFilename},
    );

    return _notActive( $session, 'scan', $web, $topic ) unless ( $av->ping );

    foreach my $fn ( grep { -f "$dir/$_" } _readdir($dh) ) {
        Foswiki::Func::writeDebug("Found file to scan:  $fn") if TRACE;
        my @results = $av->scan("$dir/$fn");
        foreach my $x (@results) {
            Foswiki::Func::writeDebug( Data::Dumper::Dumper( \@results ) )
              if TRACE;
            if ( @$x[2] eq 'FOUND' ) {
                Foswiki::Func::writeWarning(
"$scanWeb.$scanTopic: @$x[1] detected in attachment @$x[0] during scan."
                );
                $resp .= "@$x[0] - @$x[1] - @$x[2] \n";
            }
            elsif ( @$x[2] eq 'ERROR' ) {
                Foswiki::Func::writeWarning(
"$scanWeb.$scanTopic ERROR: @$x[1] detected in attachment @$x[0] during scan."
                );
                $resp .= "@$x[0] - @$x[1] - @$x[2] \n";
            }
        }
    }

    closedir($dh);
    return _scanResult( $session, $web, $topic, $resp );

}

sub _notAuth {
    my $session = shift;
    if ($cli) {
        Foswiki::Func::loadTemplate( 'oopsclamav' . $_[0] );
        my $tml = Foswiki::Func::expandTemplate('clamav_notauth');
        return _expand( $session, $tml );
    }
    else {
        throw Foswiki::OopsException( 'clamav' . $_[0],
            def => 'clamav_notauth', );
    }
}

sub _noAttach {
    my $session = shift;
    if ($cli) {
        Foswiki::Func::loadTemplate('oopsclamavscan');
        my $tml = Foswiki::Func::expandTemplate(
            '"clamav_nodir" PARAM1="' . "$_[0].$_[1]" . '"' );
        return _expand( $session, $tml );
    }
    else {
        throw Foswiki::OopsException(
            'clamavscan',
            def    => 'clamav_nodir',
            params => ["$_[0].$_[1]"]
        );
    }
}

sub _notActive {
    my $session = shift;
    if ($cli) {
        Foswiki::Func::loadTemplate( 'oopsclamav' . $_[0] );
        my $tml = Foswiki::Func::expandTemplate('clamav_offline');
        return _expand( $session, $tml );
    }
    else {
        throw Foswiki::OopsException( 'clamav' . $_[0],
            def => 'clamav_offline', );
    }
}

sub _scanResult {
    my $session = shift;
    my $msg = ( $_[2] ) ? 'scan' : 'none';
    if ($cli) {
        Foswiki::Func::loadTemplate('oopsclamavscan');
        my $tml =
          Foswiki::Func::expandTemplate( '"clamav_'
              . $msg
              . '" PARAM1="'
              . "$_[0].$_[1]"
              . '" PARAM2="'
              . $_[2]
              . '"' );
        return _expand( $session, $tml );
    }
    else {
        throw Foswiki::OopsException(
            'clamavscan',
            def    => 'clamav_' . $msg,
            params => [ "$_[0].$_[1]", "$_[2]" ],
            web    => $_[0],
            topic  => $_[1],
        );
    }
}

sub _reloadResult {
    my $session = shift;
    if ($cli) {
        Foswiki::Func::loadTemplate('oopsclamavreload');
        my $tml = Foswiki::Func::expandTemplate('clamav_reload');
        return _expand( $session, $tml );
    }
    else {
        throw Foswiki::OopsException( 'clamavreload', def => 'clamav_reload', );
    }
}

sub _expand {
    my $session = shift;
    my $tml     = shift;
    $tml = Foswiki::Func::expandCommonVariables("$tml");

#SMELL: This call violates the Foswiki API.  But it allows the same errors to be used
# in both the web (CGI) and CLI environments.

    $tml = $session->renderer->TML2PlainText($tml);
    return "\n$tml\n\n";
}
1;

__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Author: GeorgeClark

Copyright (C) 2011 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.
