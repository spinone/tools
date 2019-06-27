# tools
Various pen testing tools

**Clickjacking.htm**  
An example HTML page to provide a clickjacking proof of concept, which displays the target URL in 
an iframe and overlays a logon form over it to demonstrate how the credentials could be harvested.
The height and width of the overlay can be adjusted via the HTML code, and the login form 
can then be dragged into position to get decent screenshots.

**SMBCheck.py**  
Sometimes, when you've got a bunch servers to do a credentialled scan on, the clients haven't set them all up right.  
This script takes the given username, password and domain, then checks that port 445 TCP is open, tries to logon and 
retrieve the share list(s) and attempts to open each of them, reporting if there's any issues doing so. 
It will  accept single targets, file lists or CIDR ranges.  
It's quick and dirty, but it's much faster than running a credentialled scan again.


