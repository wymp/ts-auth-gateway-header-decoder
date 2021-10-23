import * as fs from "fs";
import { createRequest, createResponse } from "node-mocks-http";
import * as jwt from "jsonwebtoken";
import { getAuthGatewayHeaderDecoder } from "../src";







describe('Auth Gateway Header Decoder', () => {
  // Setup

  const signingKey = fs.readFileSync("./tests/api-gateway.ecdsa.pem", "utf8");
  const verificationKey = fs.readFileSync("./tests/api-gateway.ecdsa.pem.pub", "utf8");
  const badKey = fs.readFileSync("./tests/api-gateway-bad.ecdsa.pem", "utf8");

  let handler = getAuthGatewayHeaderDecoder(verificationKey);

  let nextCounter = 0;
  let nextError: any;
  let next = (err?: any) => {
    if (typeof err === "undefined") {
      nextCounter++;
    } else {
      nextError = err;
    }
  }

  const authData = {
    t: 0,
    c: "abcde12345",
    a: false,
    r: [],
    ip: "127.0.0.1",
    u: {
      sid: "aaaabbbb",
      id: "ccccdddd",
      r: [],
    }
  }

  beforeEach(function() {
    nextCounter = 0;
    nextError = null;
  });



  // Tests

  test("should respond with 400 Bad Request on request with invalid x-auth-info-signed header", async () => {
    const req = createRequest({
      headers: {
        "x-auth-info": "asdfasdf",
        "x-auth-info-signed": "false",
      }
    });
    const res = createResponse();

    handler(req, res, next);
    expect(nextError.status).toBe(400);
    expect(nextError.subcode).toBe("REQ-AUTH-BAD-SIGNED-HEADER");
  });

  test("should respond with 401 unauthorized on request with no x-auth-info header", async () => {
    const req = createRequest();
    const res = createResponse();

    handler(req, res, next);
    expect(nextError).not.toBeNull();
    expect(nextError.status).toBe(401);
    expect(nextError.subcode).toBe("REQ-AUTH-NO-HEADER");
  });

  test("should respond with 401 Unauthorized on request with blank x-auth-info header", async () => {
    const req = createRequest({
      headers: {
        "x-auth-info": ""
      }
    });
    const res = createResponse();

    handler(req, res, next);
    expect(nextError.status).toBe(401);
    expect(nextError.subcode).toBe("REQ-AUTH-NO-HEADER");
  });

  test("should respond with 400 Bad Request on request with unencrypted header when signing not disabled with an x-auth-info-signed header", async () => {
    const req = createRequest({
      headers: {
        "x-auth-info": JSON.stringify(authData)
      }
    });
    const res = createResponse();

    handler(req, res, next);
    expect(nextError.status).toBe(400);
    expect(nextError.subcode).toBe("REQ-AUTH-INVALID-JWT");
  });

  test("should respond with 400 BadRequest on request with header encrypted with incorrect creds", async () => {
    const req = createRequest({
      headers: {
        "x-auth-info": jwt.sign(
          authData,
          badKey,
          {
            algorithm: "ES256",
            audience: "some-audience",
            expiresIn: 30,
          }
        )
      }
    });
    const res = createResponse();

    handler(req, res, next);
    expect(nextError.status).toBe(400);
    expect(nextError.subcode).toBe("REQ-AUTH-INVALID-JWT");
  });

  test("should respond with 401 Unauthorized on request with expired auth header", async () => {
    const data: any = authData;
    data.iat = Math.floor(Date.now() / 1000) - 30;

    const req = createRequest({
      headers: {
        "x-auth-info": jwt.sign(
          data,
          signingKey,
          {
            algorithm: "ES256",
            audience: "some-audience",
            expiresIn: 1,
          }
        )
      }
    });
    const res = createResponse();

    handler(req, res, next);
    expect(nextError.status).toBe(401);
    expect(nextError.subcode).toBe("REQ-AUTH-EXPIRED-JWT");
  });

  test("should pass to next on success", async () => {
    const req = createRequest({
      headers: {
        "x-auth-info": jwt.sign(
          authData,
          signingKey,
          {
            algorithm: "ES256",
            audience: "some-audience",
            expiresIn: 3000,
          }
        )
      }
    });
    const res = createResponse();

    handler(req, res, next);
    expect(nextCounter).toBe(1);
    expect(req.auth).toBeDefined();
    expect(req.auth.u).toBeDefined();
    expect(req.auth.u.id).toBe(authData.u.id);
  });

  test("should successfully unpack an unsigned auth header", async () => {
    const req = createRequest({
      headers: {
        "x-auth-info": JSON.stringify(authData),
        "x-auth-info-signed": "0",
      }
    });
    const res = createResponse();

    handler(req, res, next);
    expect(nextCounter).toBe(1);
    expect(req.auth).toBeDefined();
    expect(req.auth.u).toBeDefined();
    expect(req.auth.u.id).toBe(authData.u.id);
  });

  test.todo("should default to signing with ES256 if not otherwise specified");
  test.todo("should be able to decode other signing algorithms if specified using x-auth-info-algorithm header");
});



