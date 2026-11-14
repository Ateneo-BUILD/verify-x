# Third-party notices

The Apache License 2.0 in [`LICENSE`](LICENSE) covers the code and
documentation written for this project by Ateneo de Manila University -
Business Insights Laboratory for Development - Technical Resource Lab
("Ateneo BUILD-TRL"), with the attribution in [`NOTICE`](NOTICE). The files and services below are not
covered by it, or are covered only as stated.

## Included in this repository under their own licenses

| Path | Component | License |
|---|---|---|
| `static/jsQR.min.js` | [jsQR](https://github.com/cozmo/jsQR) 1.4.0, as minified by jsDelivr. Copyright Cosmo Wolfe and contributors. | Apache License 2.0, the same text as [`LICENSE`](LICENSE) |

## From BUILD-TRL's OfflineVerifier project

`ovcrypto/` and `vectors/vectors.json` are copied verbatim from the sibling
OfflineVerifier project. BUILD-TRL holds the copyright in both projects, and
licenses these copies under the Apache License 2.0 as part of this
repository. The test vectors hold test-only key material, not keys any
deployment uses.

## Loaded at runtime, not distributed here

The pages load these from the network. This repository contains no copy of
them, and their own terms apply:

- **eVerify liveness SDK**, from `https://liveness.everify.gov.ph/`, by the
  Philippine Statistics Authority (PSA).
- **qrcode-generator** 1.4.4 by Kazuhiko Arase, from jsDelivr, under the MIT
  License.

Python dependencies are installed from `requirements.txt` and are not
redistributed here.

## Marks and personal data: not licensed

The Apache License grants no rights in trade names, trademarks, service
marks or product names (Section 6). None of the following is licensed. They
are included only so the application and its documentation render as
intended:

- **PSA marks:** `static/PSAAuthenticationStamp.png` and
  `static/nationalid-everify-logo.png`, the Philippine Statistics
  Authority's National ID and eVerify marks.

Neither the application nor its documentation carries any other
organization's marks: a site shows the name and logos its operator
configures (`SITE_TITLE`, `SITE_FOOTER_LOGOS`), and the slide decks carry a
brand only when one is supplied to them (`DECK_BRAND`).

Sample people in the documentation and demo data, including names, National
ID numbers beginning `0000-`, digital IDs beginning `SMP` and the portrait in
`static/sample-id1.png`, are synthetic and do not describe real people.
