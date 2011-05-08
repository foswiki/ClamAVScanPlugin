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

our $VERSION           = '$Rev$';
our $RELEASE           = '1.0.0';
our $SHORTDESCRIPTION  = 'Scans attachments for viruses during upload';
our $NO_PREFS_IN_TOPIC = 1;

my $clamdPort;              # Unix socket used to communicate with clamd daemon

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
    Foswiki::Func::registerRESTHandler( 'reload', \&_reloadSignatures );

    # Request clamd to scan the attachments of a topic
    Foswiki::Func::registerRESTHandler( 'scan', \&_scanAttachments );

    # Plugin correctly initialized
    return 1;
}

=begin TML

---++ StaticMethod _CLAMAVSTATUS() -> $string

Registered Handler: Implements the CLAMAVSTATUS macro. Returns the status string.

=cut

sub _CLAMAVSTATUS {

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

Passes the stream to clamd for scanning.  Throws an exception under two conditions:
   * clamd daemon is not available, and mandatoryScan requested
   * clamd reported a threat in the file.

=cut

sub beforeUploadHandler {
    my ( $attrs, $meta ) = @_;

    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort" );
    unless ( $av->ping ) {
        return unless $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{mandatoryScan};
        throw Foswiki::OopsException(
            'clamavattach',
            def    => 'clamav_offline',
            params => [ $attrs->{name} ]
        );
    }

    my ( $ok, $virus ) = $av->scan_stream( $attrs->{stream} );

    if ( $ok eq 'FOUND' ) {
        Foswiki::Func::writeEvent("ClamAV","$virus detected in attachment $attrs->{name} - Upload blocked.");
        throw Foswiki::OopsException(
            'clamavattach',
            def    => 'clamav_upload',
            params => [ $attrs->{name}, $virus ]
        );
    }

    return 1;
}

=begin TML

---++ StaticMethod beforeSaveHandler()

Intercepts an upated topic prior to save.

Passes the topic text to clamd for scanning.  Throws an exception:
   * scanTopics requested and clamd reported a threat in the file.

=cut

sub beforeSaveHandler {
    my ( $text, $topic, $web, $meta ) = @_;

    return unless $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{scanTopics};

    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort" );

    my ( $ok, $virus ) = $av->scan_string($text);

    if ( $ok eq 'FOUND' ) {
        Foswiki::Func::writeEvent("ClamAV","$virus detected in topic text during save - Save blocked.");
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

    return "Not authorized" unless Foswiki::Func::isAnAdmin();
    Foswiki::Func::writeEvent("ClamAV","Signature reload requested.");
    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort" );
    unless ( $av->ping ) {
        return "clamd not available: " . $av->errstr();
        }
    $av->reload();

    return "Reload of ClamAV virus signatures requested\n";
}

=begin TML

---++ StaticMethod scanAttachments($session) -> $text

Implements the rest handler "scan"

Performs a virus scan of all attachment for a topic.  This includes the rcs ",v"
files.  It's important to scan data stored in the prior revisions of a file.

This function is only available to administrators.

=cut

sub _scanAttachments {
    my $session = shift;
    return "Not authorized" unless Foswiki::Func::isAnAdmin();

    my $query   = Foswiki::Func::getCgiQuery();
    my $resp = '';

    my $nl = ( Foswiki::Func::getContext()->{'command_line'} ) ?  "\n" : '<br />';

    my $topic = $query->param('topic');
    my $web;
    ( $web, $topic ) = Foswiki::Func::normalizeWebTopicName( undef, $topic );

    my $dir  = "$Foswiki::cfg{PubDir}/$web/$topic";
    my $dh;
    opendir( $dh, $dir ) || return "No attachment directory found for $topic $nl";

    my $av =
      new Foswiki::Plugins::ClamAVScanPlugin::ClamAV( port => "$clamdPort", find_all => 1, forceScan => 1);

    foreach my $fn ( grep { -f "$dir/$_"}readdir($dh) ) {
        my @results = $av->scan( "$dir/$fn" );

        foreach my $x ( @results) {
            $resp .=  "@$x[0] - @$x[1] - @$x[2] $nl";
        }
    }
    closedir($dh);
    return $resp . $nl;
}

1;

__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Author: GeorgeClark

Copyright (C) 2008-2011 Foswiki Contributors. Foswiki Contributors
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
