const jose = require('jose');
const fs = require('fs');
const crypto = require('crypto');

async function getPrivateJwk() {
    // 1. อ่านไฟล์ Private Key (รูปแบบ PKCS#8)
    const privateKeyPem = fs.readFileSync('./private.pem', 'utf8');

    // 2. นำเข้า PEM และแปลงเป็น Key Object
    // หมายเหตุ: หากไฟล์เป็นรูปแบบดั้งเดิม (PKCS#1) ให้ใช้ importPKCS1
    // let privateKey;

    // try {
    //     // ลองใช้ PKCS#8 ก่อน
    //     privateKey = await jose.importPKCS8(privateKeyPem, 'RS256');
    // } catch (error) {
    //     // ถ้าไม่ได้ ลอง PKCS#1
    //     console.log("Trying PKCS#1 format...");
    //     privateKey = await jose.importPKCS1(privateKeyPem, 'RS256');
    // }
    // 3. Export เป็น JWK (จะได้ JSON ที่มีค่าลับ เช่น d, p, q)
    // const privateJwk = await jose.exportJWK(privateKey);
    // 2. ใช้ crypto module แปลง PEM → JWK (รองรับทั้ง PKCS#1 และ PKCS#8)
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const privateJwk = privateKey.export({ format: 'jwk' });

    // เพิ่ม Metadata เพื่อใช้ระบุตัวตนของคีย์
    privateJwk.kid = "key-id-2026";
    privateJwk.use = "sig";
    const publicJwk = getPublicJwk(privateJwk);
    console.log("--- Private JWK (เก็บเป็นความลับสูงสุด) ---");
    console.log(JSON.stringify(privateJwk, null, 2));

    return { privateKey, publicJwk };
}
function getPublicJwk(privateJwk) {
    const { d, p, q, dp, dq, qi, ...publicJwk } = privateJwk;
    return publicJwk;
}


async function createToken() {
    const { privateKey } = await getPrivateJwk();

    const jwt = await new jose.SignJWT({ 'role': 'admin', 'user_id': '123' })
        .setProtectedHeader({ alg: 'RS256', kid: 'key-id-2026' })
        .setIssuedAt()
        .setIssuer('https://your-auth-server.com')
        .setExpirationTime('1h')
        .sign(privateKey);

    console.log("Generated JWT:", jwt);
}

createToken();
