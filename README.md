Auth Gateway Header Decoder
========================================================================

*A small Express middleware that decodes the auth header from a request forwarded by a
[wymp auth gateway](https://github.com/wymp/auth-gateway) and throws an error on problems.*

This library provides functionality that can be used to decode and attach auth information passed
via an auth gateway. This philosophy for managing requests and mapping them to back-end services is
more fully explained in the
[wymp auth gateway readme](https://github.com/wymp/auth-gateway#readme);

Because the header is expected to be a signed JWT, it can serve as a general authorization token
used to guarantee that requests are originating from the designated api auth gateway. On decode, the
data contained in the token represents the user and request authentication data for the request and
is attached to the `request` object as a new `auth` property. This property can be verified at
runtime using the various
[authd request assertion functions](https://github.com/wymp/ts-http-utils/blob/d7a65ed0f0f357d33f560577003653b86304b733/src/index.ts#L38)
defined in [@wymp/ts-http-utils](https://github.com/wymp/ts-http-utils).

## Usage

To use the library, simply add it as the first middleware on your app:

```ts
import * as express from "express";
import { getAuthGatewayHeaderDecoder } from "@wymp/auth-gateway-header-decoder";
import { assertAuthdReq } from "@wymp/http-utils";
import * as fs from "fs";

const app = new express();

// Get the public key from somewhere for verifying requests. This could come from a file, as
// indicated here, or it could come from an environment variable. Either way, it should be a public
// key string compatible with the `jsonwebtoken` library.
const gatewayPubkey = fs.readFileSync("./auth-gateway.pem.pub").toString("utf8");
app.use(getApiGatewayReceiver(gatewayPubkey));

app.get("/", (req, res, next) => {
  // The middleware we used should have parsed the JWT out of the header and attached it as the
  // `auth` property on the request object. We'll use `http-util`'s `assertAuthdReq` function to
  // assert this is the case. This will throw an error if the object does not conform. If it does,
  // the object will be correctly typed as an "AuthdRequest" (see below).
  assertAuthdReq(req);

  // Now you have an auth property on your req object
  //
  // This new property's shape is defined in [`@wymp/types`](https://github.com/wymp/ts-types/blob/c186ce316dc689cd7b913abde3ceb4bb562b7da4/src/Auth.ts#L25)
  // For convenience, it is defined as follows (read more about this via the link):
  // 
  // export type ReqInfoString = {
  // 	t: 0;
  // 	c: string;
  // 	a: boolean;
  // 	r: Array<string>;
  // 	ip: string;
  // 	d?: boolean;
  // 	u?: {
  // 		sid: string;
  // 		id: string;
  // 		r: Array<string>;
  // 		s?: Array<string> | null;
  // 	};
  // };
  // export type ReqInfoBitwise = {
  // 	t: 1;
  // 	c: string;
  // 	a: boolean;
  // 	r: number;
  // 	ip: string;
  // 	d?: boolean;
  // 	u?: null | {
  // 		sid: string;
  // 		id: string;
  // 		r: number;
  // 		s?: number | null;
  // 	};
  // };
  // export type ReqInfo = ReqInfoString | ReqInfoBitwise;
  //

  const text: Array<string> = [];

  text.push(`The client ID used for this request is ${req.auth.c}`);
  text.push(`The client ${req.auth.a ? "DID" : "DID NOT"} pass a valid secret`);
  text.push(`The client's roles are the following: '${req.auth.t === 0 ? req.auth.r.join("', '") : req.auth.r}'`);
  text.push(`The IP address of the request is ${req.auth.ip}`);
  text.push(`Debugging is ${req.auth.d ? "ON" : "OFF"} for this request.`);

  if (req.auth.u) {
    text.push(`This request is from a logged in user.`);
    text.push(`The user's id is ${req.auth.u.id}`);
    text.push(`The user's session id for this session is ${req.auth.u.sid}`);
    text.push(`The user's roles are the following: '${req.auth.t === 0 ? req.auth.u.r.join("', '") : req.auth.u.r}'`);
    if (req.auth.u.s) {
      text.push(`This is a 3rd-party OAUTH request on behalf of the given user.`);
      text.push(`The OAuth scopes for this request are: '${req.auth.t === 0 ? req.auth.u.s.join("', '") : req.auth.u.s}'`);
    } else {
      text.push(`This is NOT an oauth request.`);
    }
  } else {
    text.push(`This request does NOT have a logged in user associated with it.`);
  }

  res.set("Content-Type", "text/plain");
  res.send(`Request Info\n=============================\n\n${text.join("\n")}`);
});
```

Note that if you have configured your auth gateway to use a different header name, you can configure
that by passing the base header name as the second argument to the `getAuthGatewayHeaderDecoder`
function.

