# Vendored protocol registration component

This directory contains the protocol registration component used by the parent project. It is kept as source so the parent application can launch it as a subprocess.

Install the dependencies in `requirements.txt` when using the standalone WebUI. The parent application manages its own dependency set at the repository root.

The upstream license is included in `LICENSE`. Runtime databases, mailbox contents, proxy credentials, and local logs must stay outside version control.
