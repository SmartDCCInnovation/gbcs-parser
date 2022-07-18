# GBCS Parser

Tool based on [HenryGiraldo/gbcs-parser-js][gbcs-parser-js], which is a super
useful browser based [GBCS][gbcs] parser. It has been uplifted to use TypeScript
and output JSON instead of performing DOM manipulations. In addition, to allow
running from NodeJS the crypto API was exchanged for the NodeJS [Crypto
API][crypto].

The parser is aimed at being used with [DCC Boxed][boxed], so does not need full
coverage of GBCS. As such, support for GBT has been removed. It has been tested
against `RTDS 4.5.0` (Reference Test Data Set).


## Usage

Developed against `node 16`.

TODO


## Other Info

Copyright 2022, Smart DCC Limited, All rights reserved. Project is licensed under GLPv3.


[gbcs-parser-js]: https://github.com/HenryGiraldo/gbcs-parser-js "GitHub: GBCS Parser JS"
[crypto]: https://nodejs.org/docs/latest-v14.x/api/crypto.html "NodeJS Crypto API v14.x"
[gbcs]: https://smartenergycodecompany.co.uk/the-smart-energy-code-2/ "Smart Energy Code"
[boxed]: https://www.smartdcc.co.uk/our-smart-network/network-products-services/dcc-boxed/ "DCC Boxed"