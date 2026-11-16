# Contributing

Questions, bug reports and proposals for Verify are welcome. This page says
how to send one, and how a change reaches this repository.

## Ways to contribute

- **Ask a question.** If the README, the
  [manual](docs/user-manual.pdf) or the
  [deployment guide](docs/deploy-aws.md) leaves something unclear, open an
  issue.
- **Report a bug.** Say which release you run ([`VERSION`](VERSION)), what
  you did, what you expected and what happened.
- **Propose a change.** Open an issue that says what should change and why,
  before you write much code.

A security flaw is the exception. Do not open an issue for one: report it
privately, as [SECURITY.md](SECURITY.md) describes.

## What makes a report easy to act on

- The release, and how the site is run: locally, or deployed with the site
  kit.
- The steps, and the error or the log lines that go with them.
- Invented data only. Never post a real person's details, the number or
  code of a real ID, a credential or a key. Take them out of logs and
  screenshots first.

## Working on the code

The [README](README.md) says how to run Verify locally. Before you send a
change:

- Run the tests, `venv/bin/python manage.py test accounts`. They must pass,
  and a change in behaviour comes with a test that pins it.
- Turn on the pre-push guard, `git config core.hooksPath tools/hooks`, so a
  credential or a key cannot leave your machine in a push.
- Keep a deployment's settings out of the repository. The site kit carries
  no site's values, and the tests refuse an account id, a resource id or an
  address in `terraform/` or `deploy/`.

## How a change reaches this repository

This repository is published from a source kept elsewhere. Each publication
is one commit, checked and tested as a whole. So:

- A pull request is welcome as a way to show the change you propose, but it
  is not merged as it stands. An accepted change is made at the source and
  arrives here with the next publication.
- The commits here are publications. Each says what changed for someone who
  runs a site.

## License of contributions

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the license of this repository, as its
Section 5 provides, and that you have the right to offer it.

## Credit

People whose reports or proposals change Verify are named in
[CONTRIBUTORS.md](CONTRIBUTORS.md), with their agreement.

## Conduct

The [code of conduct](CODE_OF_CONDUCT.md) applies to issues, pull requests
and every other place where this project is discussed.
