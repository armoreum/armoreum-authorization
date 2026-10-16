# Source scope and provenance

This is a module extraction from the supplied Armoreum artifacts, not a recovered original standalone workspace package. The main application and full contract repositories remain the canonical source snapshots.

`SOURCE_MANIFEST.json` identifies the source repository, source commit, original path, copied path, and SHA-256 digest of each copied file. Shared files are included when needed to preserve local dependency closure. No backend implementation, database, live credentials, or operational records are invented.

Module-specific Node tests can be run with the declared dependencies. Their results do not prove complete browser behavior, Solidity compilation, onchain configuration, or production safety. Third-party Solidity imports are external dependencies and retain their own licenses.

This repository is publicly MIT-licensed for project-owned source. `private: true` in the npm manifest prevents accidental registry publication and does not make the GitHub repository private. GitHub Releases distribute source archives; no npm or GitHub Packages registry publication is implied.
