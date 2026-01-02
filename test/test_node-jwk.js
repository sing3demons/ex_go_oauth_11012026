const rsaSign = require("jsrsasign");
const fs = require("fs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const jwkToPem = require('jwk-to-pem')



function generateJWK({ pemKey, extraKey, outputJWK }) {
    const jwkObject = {
        kty: "",
        e: "",
        n: ""
    };

    try {
        if (!pemKey) {
            return {
                err: true,
                result_desc: "missing_key_data"
            };
        }

        const cFormatStart = /^-----BEGIN(\s{1}|\s{1}[A-Z]+\s{1})(PRIVATE|PUBLIC) KEY-----/.test(pemKey);
        const cFormatEnd = /^-----END(\s{1}|\s{1}[A-Z]+\s{1})(PRIVATE|PUBLIC) KEY-----/.test(
            pemKey.split("\n").slice(-2)[0]
        );
        if (!cFormatStart && !cFormatEnd) {
            return {
                err: true,
                result_desc: "invalid_format"
            };
        }

        const decryptedJWK = rsaSign.KEYUTIL.getJWK(pemKey, true, true, true, true);
        const cFormatPrivate = /^-----BEGIN(\s{1}|\s{1}[A-Z]+\s{1})PRIVATE KEY-----/.test(pemKey);
        if (cFormatPrivate) {
            console.log(`outputJWK is ${outputJWK}`);
            if (outputJWK === "private") {
                Object.assign(jwkObject, decryptedJWK);
            } else {
                jwkObject.kty = decryptedJWK.kty;
                jwkObject.e = decryptedJWK.e;
                jwkObject.n = decryptedJWK.n;
            }
        } else {
            jwkObject.kty = decryptedJWK.kty;
            jwkObject.e = decryptedJWK.e;
            jwkObject.n = decryptedJWK.n;
        }

        console.log("assign key is", extraKey);
        if (typeof extraKey === "object" && Object.keys(extraKey).length > 0) {
            Object.assign(jwkObject, extraKey);
        }

        return {
            err: false,
            result_desc: "success",
            jwkObject
        };
    } catch (error) {
        console.log("[utils.generateJWK] Catch: ", error.stack);
        return {
            err: true,
            result_desc: error.message
        };
    }
}

function verifyPublicKeys({ token, jwks }) {

    try {
        let message = null;
        for (const jwk of jwks) {
            try {
                const pem = jwkToPem(jwk);
                const payload = jwt.verify(token, pem);
                console.log("!!! VERIFY TOKEN IS SUCCESS !!!");
                return {
                    err: false,
                    result_desc: "success",
                    result_data: payload
                };
            } catch (error) {
                message = error.message;
            }
        }

        return {
            err: true,
            result_desc: message
        };
    } catch (error) {
        console.log("[utils.verifyPublicKeys] Catch: ", error.stack);
        return {
            err: true,
            result_desc: error.message
        };
    }
}

function generateJWT(header, signature, payload) {
    let result;
    try {
        if (header && payload && signature) {
            let token = jwt.sign(payload, signature.private_key, {
                header: header
            });

            return (result = {
                err: false,
                result_desc: "success",
                jwt_code: token
            });
        } else {
            return (result = {
                err: true,
                result_desc: "cannot generateJWT"
            });
        }
    } catch (error) {
        console.log("ERROR_MESSAGE:", error.message);
        return (result = {
            err: true,
            result_desc: error.message
        });
    }
};

function main() {
    const pemKey = fs.readFileSync("./private.pem", "utf8");

    const enhance_oidc_data = {
        private_key: pemKey,
        expire_token: Date.now() + 3600 * 1000,
        iat: Date.now(),
        current_time: Date.now()
    };

    const extraKey = {
        kid: "my-key-id",
        use: "sig",
        alg: "RS256"
    };
    // const outputJWK = "private"; // or "public"
    const outputJWK = "public"

    const headerJWT = {
        alg: "RS256",
        typ: "JWT",
        kid: extraKey.kid
    };
    const signature = {
        private_key: enhance_oidc_data.private_key
    };

    const payload = {
        iss: "admd",
        sub: "idToken",
        aud: "client123",
        exp: Math.floor(enhance_oidc_data.expire_token / 1000),
        iat: Math.floor(enhance_oidc_data.iat / 1000),

    };

    const token = generateJWT(headerJWT, signature, payload)
    if (!token.err) {
        console.log("Generated JWT:", token.jwt_code);
    } else {
        console.error("Error generating JWT:", token.result_desc);
    }

    const result = generateJWK({ pemKey, extraKey, outputJWK });
    if (!result.err) {
        console.log("Generated JWK:", result.jwkObject);
    } else {
        console.error("Error generating JWK:", result.result_desc);
    }

    const verifyResult = verifyPublicKeys({ token: token.jwt_code, jwks: [result.jwkObject] });
    if (!verifyResult.err) {
        console.log("Verified JWT Payload:", verifyResult.result_data);
    } else {
        console.error("Error verifying JWT:", verifyResult.result_desc);
    }




}
main();