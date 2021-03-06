import * as jwt from "jsonwebtoken";
import * as E from "@wymp/http-errors";

/**
 * Takes a public verification key and returns a handler that uses that key to decode
 * an incoming JWT expected in the `x-api-gateway-auth` header.
 *
 * Throws errors on various conditions and calls `next` on success.
 *
 * In this case, we're keeping this function _very_ agnostic. It conforms to the very basic
 * structures of an Express middleware function, but with many fewer requirements. This means it
 * can stay versatile and adaptable to upstream changes while still performing its core
 * functionality reliably.
 *
 * @param pubkey - A string representation of the public key used to sign the header (this assumes
 * the algorithm is ES256; for now that's the only actual accepted algorithm). Key should be a
 * standard PEM-formatted ECDSA public key.
 * @param headerName - An optional parameter allowing you to specify the base name of the header
 * used to pass auth information. There are three possible headers that a gateway can use to pass
 * auth info:
 *   * `[headerName]` is the actual auth info object, which is either a signed JWT (default) or a
 *     JSON object.
 *   * `[headerName]-signed` should be "0", "1" or undefined (defaults to "1" if undefined) and
 *     specifies whether or not the auth info object is signed.
 *   * `[headerName]-algorithm` should be one of the algorithms specified in the
 *     [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) library. For now, the only
 *     accepted value is `ES256`.
 * @returns An express middleware that will respond with an error if the auth gateway handshake
 * isn't correct.
 */
export const getAuthGatewayHeaderDecoder = (pubkey: string, headerName: string = "x-auth-info") => {
  return <T extends { header: (nm: string) => (string | undefined); }>(
    req: T,
    res: unknown,
    next: Function
  ): void => {
    try {
      const authHeader = req.header(headerName) || "";
      const signedHeader = req.header(`${headerName}-signed`);
      const algoHeader = req.header(`${headerName}-algorithm`);

      // Validate 'signed' header format
      if (signedHeader && !(signedHeader === "1" || signedHeader === "0")) {
        throw new E.BadRequest(
          `Bad 'signed' header ('${headerName}-signed'). Should be "1", "0" or undefined, but ` +
          `got '${signedHeader}'`,
          `REQ-AUTH-BAD-SIGNED-HEADER`
        );
      }

      // Default 'signed' to true if header not present
      const signed = signedHeader ? Boolean(Number(signedHeader)) : true;

      // Validate 'algorithm' header value, defaulting to "ES256" if header not present
      const algorithm: string = algoHeader || "ES256";
      verifyAlgorithm(algorithm);

      // Throw if no auth header provided
      if (!authHeader || authHeader.trim() === "") {
        throw new E.Unauthorized(
          `Request must come through valid wymp auth gateway (no '${headerName}' header found).`,
          `REQ-AUTH-NO-HEADER`
        );
      }

      // Otherwise, try to verify and inflate header
      // Here, we're happy assuming that if we have a valid, signed header it is also a valid
      // Auth.ReqInfo object, so we're just casting.
      (req as any).auth = signed
        ? jwt.verify(authHeader, pubkey, { algorithms: [algorithm] })
        : JSON.parse(authHeader);

      // Continue with request processing
      next();
    } catch (e) {
      let err: Error = e;
      if (e.name) {
        if (e.name === "JsonWebTokenError") {
          err = new E.BadRequest(
            `'${headerName}' header not a valid JWT. This header must be a JWT signed by a Wymp ` +
            `auth gateway: ${e.message}`,
            `REQ-AUTH-INVALID-JWT`
          );
        } else if (e.name === "TokenExpiredError") {
          err = new E.Unauthorized(
            `Invalid '${headerName}' header: The JWT has expired.`,
            `REQ-AUTH-EXPIRED-JWT`
          );
        }
      }
      next(err);
    }
  }
}

function verifyAlgorithm(algo: string): asserts algo is jwt.Algorithm {
  const valid: Array<jwt.Algorithm> = [
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "none",
  ];
  if (!valid.includes(algo as jwt.Algorithm)) {
    throw new E.BadRequest(
      `This request was signed using an unsupported algorithm: '${algo}'. Supported algorithms ` +
      `include '${valid.join("', '")}'`,
      `REQ-AUTH-UNSUPPORTED-ALGORITHM`
    );
  }
}

