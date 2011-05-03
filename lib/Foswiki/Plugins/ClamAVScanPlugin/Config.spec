# ---+ Extensions
# ---++ ClamAVScanPlugin
# **PATH**
# Specify the port used for the connection between Foswiki and the clamd backend.
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
