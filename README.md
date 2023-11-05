# ScanMyCode
Open Source Code Vulnerability Scanner
This scanner focuses on the following vulnerabilities:

* Command injection                 ... v.1
* Weak or hardcoded passwords
* Buffer overflow risk              ... v.1
* Memory corruption risk            ... v.1
* Vulnerable third-party libraries

The main Components of the tool are:

* Scanner Module: This module scans the code and analyzes it looking for patterns, loopholes and anything that indicates the vulnerabilities listed in the section above.
* Database of Vulnerabilities: A database containing information about known vulnerabilities, patterns, and signatures for comparison.
* Reporting Module: Generates detailed reports that highlight identified vulnerabilities, their location, severity, and suggested remediation.
* User Interface: A simple command-line interface for users to interact with the tool, and view reports. (Configuration of scanning options will be added shortly)

