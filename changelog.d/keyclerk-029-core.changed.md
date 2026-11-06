- The core is ready for KeyClerk 0.29.0: the installer writes `identity.pub` (the public half of `mark.key`), which
  the checking signer pins with `--identity-key`, and `install.py upgrade-0.29` moves an installed core over: the
  desk's bundle and unlock keys into the signer, then the reconciler, the signer and the desk in that order. Merged
  with the KeyClerk 0.29.0 pin.
