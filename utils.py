"""Shared validation and redaction helpers for OSINTPRO modules.

The current production server is still a standard-library HTTP app. These
module facades make the core behavior easier to test and migrate without
introducing Flask or third-party runtime dependencies.
"""

from __future__ import annotations

import server


clean_domain = server.clean_domain
clean_username = server.clean_username
redact_text = server.redact_text
redact_data = server.redact_data
safe_download_filename = server.safe_download_filename
feature_allowed = server.feature_allowed
public_feature_flags = server.public_feature_flags
