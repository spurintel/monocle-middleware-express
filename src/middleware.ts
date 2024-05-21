import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { serialize, parse } from 'cookie';
import { compactDecrypt, importPKCS8 } from 'jose';
import { TextDecoder } from 'util';
import axios from 'axios';
import path from 'path';

async function monocleMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    const cookies = parse(req.headers['cookie'] || '');
    const mclValidCookie = cookies['MCLVALID'];

    if (!mclValidCookie && req.path !== '/verify-monocle' && req.path !== '/denied') {
        console.log('No MCLVALID cookie found');
        const siteToken = process.env.SITE_TOKEN;
        res.render(path.join(__dirname, '..', 'views', 'monocle_captcha_page'), { siteToken });
        return;
    } else if (req.path === '/denied') {
        //  the service should be in the query string
        const service = req.query.service;
        console.log('Rendering denied page with service:', service)
        res.render(path.join(__dirname, '..', 'views', 'denied'), { service });
        return;
    } else if (mclValidCookie) {
        const cookieValid = await validateCookie(req, process.env);
        if (!cookieValid) {
            console.log('Invalid MCLVALID cookie found');
            const siteToken = process.env.SITE_TOKEN;
            res.render(path.join(__dirname, '..', 'views', 'monocle_captcha_page'), { siteToken });
            return;
        }
    }

    if (req.path === '/verify-monocle' && req.method === 'POST') {
        console.log('Verifying Monocle captcha');
        const decryptionMethod = process.env.DECRYPTION_METHOD;
        if (decryptionMethod === 'user-managed') {
            console.log('Using user-managed decryption method');
            validateCaptchaUserManaged(req, res, process.env).then(({ status, body, headers }) => {
                console.log("Status: ", status, " Body: ", body, " Headers: ", headers)
                if (headers) {
                    console.log('Settings headers: ', headers);
                    res.set(headers);
                }
                res.status(status).send(body);
            });
        } else if (decryptionMethod === 'spur-managed') {
            console.log('Using spur-managed decryption method');
            validateCaptchaSpurManaged(req, res, process.env).then(({ status, body, headers }) => {
                console.log("Status: ", status, " Body: ", body, " Headers: ", headers)
                if (headers) {
                    res.set(headers);
                }
                res.status(status).send(body);
            });
        } else {
            console.error('Invalid DECRYPTION_METHOD environment variable');
            res.status(500).send("Invalid DECRYPTION_METHOD environment variable");
        }
    } else {
        next();
    }
}

function hexToBuf(hex: string) {
    return Buffer.from(hex, 'hex');
}

function bufToHex(buffer: Buffer) {
    return buffer.toString('hex');
}

export async function setSecureCookie(request: Request, res: Response, env: NodeJS.ProcessEnv) {
    const clientIpAddress = request.headers['x-forwarded-for'] || request.ip;
    const expiryTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const cookieValue = `${clientIpAddress}|${expiryTime}`;

    const cookieSecretValue = env.COOKIE_SECRET;
    if (!cookieSecretValue) {
        throw new Error('COOKIE_SECRET is not set');
    }
    const secretKey = crypto.createSecretKey(hexToBuf(cookieSecretValue));

    const iv = crypto.randomBytes(12); // Generate a random initialization vector

    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    const encryptedValue = Buffer.concat([cipher.update(cookieValue, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const encryptedValueHex = bufToHex(encryptedValue);
    const ivHex = bufToHex(iv);
    const authTagHex = bufToHex(authTag);

    const isSecure = process.env.NODE_ENV === 'production'; // secure if in production environment
    const cookie = serialize('MCLVALID', `${ivHex}.${encryptedValueHex}.${authTagHex}`, {
        secure: isSecure,
        httpOnly: true,
        path: '/',
        sameSite: 'strict'
    });

    return { 'Set-Cookie': cookie };
}

export async function validateCookie(request: Request, env: NodeJS.ProcessEnv) {
    const cookies = parse(request.headers['cookie'] || '');
    const mclValidCookie = cookies['MCLVALID'];
    if (!mclValidCookie) {
        return false;
    }

    const [ivHex, encryptedValueHex, authTagHex] = mclValidCookie.split('.');
    if (!ivHex || !encryptedValueHex || !authTagHex) {
        return false;
    }

    const cookieSecretValue = env.COOKIE_SECRET;
    if (!cookieSecretValue) {
        throw new Error('COOKIE_SECRET is not set');
    }
    const secretKey = crypto.createSecretKey(hexToBuf(cookieSecretValue));

    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, hexToBuf(ivHex));
    decipher.setAuthTag(hexToBuf(authTagHex));

    let decryptedValue;
    try {
        decryptedValue = decipher.update(encryptedValueHex, 'hex', 'utf8') + decipher.final('utf8');
    } catch (err) {
        console.error('Failed to decrypt:', err);
        return false;
    }

    const [cookieClientIpAddress, expiryTime] = decryptedValue.split('|');

    const clientIpAddress = request.headers['x-forwarded-for'] || request.ip;
    if (clientIpAddress !== cookieClientIpAddress) {
        return false;
    }

    if (Math.floor(Date.now() / 1000) >= parseInt(expiryTime, 10)) {
        return false;
    }

    return true;
}

async function validateCaptchaUserManaged(request: Request, res: Response, env: NodeJS.ProcessEnv) {
    try {
        const captchaData = request.body.captchaData;
        const envPrivateKey = env.PRIVATE_KEY;
        if (!captchaData || !envPrivateKey) {
            return { status: 400, body: "Bad Request" };
        }
        const privateKey = await importPKCS8(envPrivateKey, "ECDH-ES");

        const decoder = new TextDecoder();
        const decryptResult = await compactDecrypt(captchaData, privateKey);
        const data = JSON.parse(decoder.decode(decryptResult.plaintext));

        const clientIpAddress = request.headers['x-forwarded-for'] || request.ip;
        const responseTime = new Date(data.ts);
        const currentTime = new Date();
        const timeDifference = Math.abs(currentTime.getTime() - responseTime.getTime()) / 1000;

        const localEnv = process.env.LOCAL;
        console.log('Local env:', localEnv)
        if (localEnv === 'true') {
            console.log('Local environment detected, skipping IP check');
            // @ts-ignore
            data.ip = clientIpAddress;
        } else {
            console.log('Local environment not detected, checking IP')
        }

        if (timeDifference > 5 || data.ip !== clientIpAddress || data.anon) {
            return { status: 403, body: JSON.stringify(data) };
        }

        const headers = await setSecureCookie(request, res, env);
        return { status: 200, body: "Captcha validated successfully", headers: headers };
    } catch (error) {
        if (error instanceof Error) {
            console.error(`Error calling third-party API: ${error.message}`);
        } else {
            console.error(`Error calling third-party API: ${error}`);
        }
        return { status: 500, body: "Internal Server Error" };
    }
}

interface ApiResponse {
    vpn: boolean;
    proxied: boolean;
    anon: boolean;
    ip: string;
    ts: string;
    complete: boolean;
    id: string;
    ipv6: string;
    service: string;
}

async function validateCaptchaSpurManaged(request: Request, res: Response, env: NodeJS.ProcessEnv) {
    const thirdPartyApiUrl = 'https://decrypt.mcl.spur.us/api/v1/assessment';
    try {
        const captchaData = request.body.captchaData;
        const envVerifyToken = env.VERIFY_TOKEN;
        if (!captchaData || !envVerifyToken) {
            return { status: 400, body: "Bad Request" };
        }

        const apiResponse = await axios.post(thirdPartyApiUrl, captchaData, {
            headers: {
                'Content-Type': 'text/plain',
                'Token': envVerifyToken,
            },
        });

        if (apiResponse.status !== 200) {
            throw new Error(`API call failed: ${apiResponse.statusText}`);
        }
        const data = apiResponse.data as ApiResponse;

        const clientIpAddress = request.headers['x-forwarded-for'] || request.ip;
        const responseTime = new Date(data.ts);
        const currentTime = new Date();
        const timeDifference = Math.abs(currentTime.getTime() - responseTime.getTime()) / 1000;

        const localEnv = process.env.LOCAL;

        console.log('Local env:', localEnv)
        if (localEnv === 'true') {
            console.log('Local environment detected, skipping IP check');
            // @ts-ignore
            data.ip = clientIpAddress;
        } else {
            console.log('Local environment not detected, checking IP')
        }

        if (timeDifference > 5 || data.ip !== clientIpAddress || data.anon) {
            console.log('Captcha validation failed for ip and data:', clientIpAddress, data);
            return { status: 403, body: JSON.stringify(data) };
        }

        const headers = await setSecureCookie(request, res, env);
        return { status: 200, body: "Captcha validated successfully", headers: headers };
    } catch (error) {
        if (error instanceof Error) {
            console.error(`Error calling third-party API: ${error.message}`);
        } else {
            console.error(`Error calling third-party API: ${error}`);
        }
        return { status: 500, body: "Internal Server Error" };
    }
}

export default monocleMiddleware;