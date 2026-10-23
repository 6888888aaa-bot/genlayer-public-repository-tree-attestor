# Design

The contract constructs a bounded GitHub tree API URL from validated owner, repository, and ref identifiers. It extracts blob paths, compares them with a comma-separated expected-path policy, hashes the complete normalized tree, and reaches consensus on the structural verdict.
