# stun-client

## Overview

A JS-based Network Address Transalation (NAT) type identifier based on the PyStun implementation originally written by gaohawk (see: https://pypi.org/project/pystun/) which follows RFC 3489 https://www.ietf.org/rfc/rfc3489.txt.

This is a modified version for https://github.com/Hutchison-Technologies/nat-type-identifier.

The main difference between this repo and the original one is

- This repo requires 0 dependencies.
- Avoid using the global socket & array in module.
- Expose the function of request stun server once and get NatType with your public ip port.
- Make it be able to customize the stun port, source ip & port.
- Support esm. (Release with dist/index.mjs)

## Features

It provides function to test the NAT type by sampling the same stun server multiple time.

By default it will request a server for `20` times. If you think it takes too long, you can change the sample count.

The return of execution will return the NAT type in use by the system running the program, the returned type will be one of the following:

```
- Blocked
- Open Internet
- Full Cone
- Symmetric UDP Firewall
- Restrict NAT
- Restrict Port NAT
- Symmetric NAT
```

To ensure the most reliable result, the program executes a number of tests which each determine the NAT type before a mode is selected from the list of results based on the most probable type. This is because issues might occur where occassional UDP packets fail to deliver.

## Usage

Sample the NAT type. (This will take a while)

```ts
const { sampleNatType } = require("@xmcl/stun-client");

const params = { sampleCount: 20, stun: "stun.sipgate.net" };

const whatsMyNat = async () => {
  const result = await sampleNatType(params);
  console.log("Result: ", result); // Outputs NAT type
  return result;
};

whatsMyNat();
```

Get the NAT type & your public ip & port. The result is not 100% reliable due to the network condition.
So we have the `sampleNatType` to increase the deterministic.

```ts
const { getNatInfoUDP, NatType } = require("@xmcl/stun-client");

const params = { stun: "stun.sipgate.net" };

const process = async () => {
  const result = await getNatInfoUDP(params);
  console.log("Result: ", result); // Outputs NAT type with public ip & port
  if (result.type !== NatType.BLOCKED) {
    const ip: string = result.externalIp
    const port: number = result.externalPort
    // handle ip and port
  } else {
    // you device is blocked...
  }
  return result;
};

process();
```

## Installation

`npm install @xmcl/stun-client`

## License

```
Copyright (c) Hutchison Technologies Ltd. MIT Licensed

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
