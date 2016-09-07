# ---+ Extensions
# ---++ ClamAVScanPlugin
# **PATH**
# Specify the Unix socket used for the connection between Foswiki and the clamd backend.
#   Ex.  <code>/tmp/clamd</code>,  <code>/var/run/clamav/clamd.sock</code>
# or <code>/var/run/clamav/clamd.ctl</code>
# The actual value is set in the clamd configuration. <br/><br/>
# Note that this can also be set to a TCP port number to connect using TCP instead of
# a Unix socket. Enter a decimal number ex. 3100, for a TCP type connection.
$Foswiki::cfg{Plugins}{ClamAVScanPlugin}{clamdPort} = '/tmp/clamd';

# **BOOLEAN**
# Should attachments be blocked if clamd is unavailable to scan attachments.
# If this option is enabled, any attempt to attach a file will result in an
# error when clamd is not available.
$Foswiki::cfg{Plugins}{ClamAVScanPlugin}{mandatoryScan} = $FALSE;

# **BOOLEAN**
# ClamAV can perform HTML scanning for certain embedded script threats.  It can also perform
# "Data Loss Prevention" through the StructuredDataDetection module.
# When DLP is enabled in clamd.conf, it will detect certain data such as social security numbers
# and credit card numbers in content.  Enable this option to perform scanning of topic data
# for structured data and embedded HTML threats.  If a threat is detected, ClamAV will
# block topic saves.
$Foswiki::cfg{Plugins}{ClamAVScanPlugin}{scanTopics} = $FALSE;

# **BOOLEAN EXPERT**
# ClamAVScanPlugin normally opens each attachment in Foswiki and then passes the file handle
# to the clamd daemon. Set this switch to force the plugin to send the file names to the 
# clamd backend.   Note that if the clamd daemon does not have authorization to read the file
# then the scan will fail.  Note that if the dependency Socket::PassAccessRights is not installed
# then filename based scans will be forced anyway.
$Foswiki::cfg{Plugins}{ClamAVScanPlugin}{forceFilename} = $FALSE;

