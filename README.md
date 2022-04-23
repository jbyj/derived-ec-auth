# Password-derived ECDSA Auth PoC

**This is NOT a reference implementation! Copying and pasting is the leading cause of code cancer.**

This is a proof of concept to replace passwords going over the wire with the use of a deterministically derived EC (in the case P-256) keys leveraging the SubtleCrypto API and JWTs.  Basically it converts a password into an ECC private key, which then is used in a pubkey auth scheme.

### Why?
Read the Medium Post https://medium.com/@jbyj/how-to-secure-your-users-passwords-don-t-send-them-ea0756a425a6

### Warnings
- **Do not use in production**.
- This is inherently less secure than other pubkey schemes due to the use of deterministically derived keys.
- It has not been cryptographically validated.
- It's got shortcuts as a PoC and is lacking much of the code needed to use in production, neither the frontend nor the backend are examples of 'good design'.

## Usage
It's a simple yarn monorepo.  Clone, then:

```shell
yarn install
yarn start
```

This will start the CRA React frontend and the Express.js backend (with nodemon).  You can play around with the code to your hearts content.

## Thoughts?
Open an issue or hit me up on Twitter [@JoshUrbane](https://twitter.com/JoshUrbane)

## License (MIT)
Copyright 2022 Josh Urbane

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
