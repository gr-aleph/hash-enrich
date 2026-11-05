"""All sources, by the name used in the response's "sources" object.

Adding a source = adding a module with an async `lookup(hash_value, hash_type, client, settings)`
that returns a SourceResult, and listing it here.
"""

from backend.sources import malwarebazaar, threatfox, virustotal

SOURCES = {
    "virustotal": virustotal.lookup,
    "malwarebazaar": malwarebazaar.lookup,
    "threatfox": threatfox.lookup,
}
