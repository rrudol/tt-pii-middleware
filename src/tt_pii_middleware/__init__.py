"""Thinking Typewriters PII middleware.

Detects and redacts Polish + universal PII before prompts leave the
in-VPC perimeter. Built on Presidio, pii-core/pii-presidio and spaCy.
"""

__version__ = "0.1.0"
