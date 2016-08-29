# See bottom of file for license and copyright information
package Foswiki::Configure::Checkers::Plugins::ClamAVScanPlugin::Enabled;

use strict;
use warnings;

use Foswiki::Configure::Checker ();
our @ISA = ('Foswiki::Configure::Checker');

sub check_current_value {
    my ( $this, $reporter ) = @_;

    my %mod = (
        name  => 'Socket::PassAccessRights',
        usage => 'Requried to pass file access rights to Clamd scanner.',
        minimumVersion => 0
    );

    Foswiki::Configure::Dependency::checkPerlModules( \%mod );
    if ( !$mod{ok} && $Foswiki::cfg{Plugins}{ClamAVScanPlugin}{Enabled} ) {
        $reporter->ERROR( $mod{check_result} );
    }
    elsif ( !$mod{ok} ) {
        $reporter->WARN( $mod{check_result} );
    }
    else {
        $reporter->NOTE( $mod{check_result} );
    }
}

1;
__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2012-2016 Foswiki Contributors. Foswiki Contributors
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
