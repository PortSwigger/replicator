# Replicator

Replicator is a Burp extension that helps developers to reproduce issues discovered by pen testers. The pen tester produces a Replicator file
which contains the findings in the report. Each finding includes a request, associated session rules or macros, and
logic to detect presence of the vulnerability. The tester sends the Replicator file to the client alongside the report.
Developers can then open the file within Burp and replicate the issues. When vulnerabilities have been fixed, Replicator
provides confirmation that the attack vector used in the pen test is now blocked. A retest is still recommended, in
case alternative attack vectors remain exploitable.

For further details, look in BappDescription.html 
