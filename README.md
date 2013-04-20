HTTPS-Finder
=======

Firefox extension for discovering HTTPS sites and creating **HTTPS Everywhere** rulesets 
[https://code.google.com/p/https-finder/][ggcode]
[ggcode]: https://code.google.com/p/https-finder/

# What is HTTPS Finder?

**HTTPS Finder** automatically detects and enforces valid HTTPS connections as you browse,
as well as automating the rule creation process for **HTTPS Everywhere** (instead of having
to manually type "https://" in the address bar to test, and writing your own XML rule for it).

The extension sends a small HTTPS request to each HTTP page you browse to.
If there is a response, the certificate is checked for validity (any certificate errors will 
result in no notification, and no further detection requests during that session).
If valid, HTTPS is automatically enforced (can be disabled for an alert only, with no redirect),
and the user is given an option to save the auto-generated rule for HTTPS Everywhere.
It is recommended to create rules whenever possible, as it more securely enforces secure connections. 
