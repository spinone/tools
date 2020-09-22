# tools
Various pen testing tools

**Clickjacking.htm**  
An example HTML page to provide a clickjacking proof of concept, which displays the target URL in 
an iframe and overlays a logon form over it to demonstrate how the credentials could be harvested.
The height and width of the overlay can be adjusted via the HTML code, and the login form 
can then be dragged into position to get decent screenshots.

**SMBCheck.py**  
Bulk SMB Credentials checker.  
Sometimes, when you've got a bunch of servers to do a credentialled scan on, the clients haven't set them all up right.  
This script takes a set of credentials (username, password and domain), then checks that port 445 TCP is open on each target, tries to logon using the given credentials, retrieves the list of shares and then attempts to open each of them, reporting if there's any issues doing so.  
It will  accept single targets, file lists or CIDR ranges.  
It's quick and dirty, but it's faster than running a credentialled scan again.  
*Requires pysmb-1.1.27 from https://pypi.org/project/pysmb/#files  * 

**checkcerts.sh**  
Checks and displays the signature algorithms for a complete certificate chain for (host:port).  
Example usage: checkcerts.sh google.com:443 
