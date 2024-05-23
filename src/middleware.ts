import {Request, Response, NextFunction} from 'express';
import crypto from 'crypto';
import {serialize, parse} from 'cookie';
import {compactDecrypt, importPKCS8} from 'jose';
import {TextDecoder} from 'util';
import path from 'path';
import { decryptAssessment } from './spur';

interface MiddlewareConfig {
    siteToken: string | undefined;
    decryptionMethod: string | undefined;
    cookieSecret: string | undefined;
    privateKey: string | undefined;
    local: string | undefined;
    verifyToken: string | undefined;
    nodeEnv: string | undefined;
}

interface ValidatedConfig {
    siteToken: string;
    decryptionMethod: string;
    cookieSecret: string;
    privateKey: string;
    local: boolean;
    verifyToken: string;
    nodeEnv: string;
    secure: boolean;
}


function createMonocleMiddleware(config: MiddlewareConfig) {
    const validatedConfig = validateConfig(config);
    if (config.decryptionMethod === 'user-managed') {
        return userManagedMiddleware(validatedConfig);
    } else if (config.decryptionMethod === 'spur-managed') {
        return spurManagedMiddleware(validatedConfig);
    } else {
        throw new Error('Invalid decryption method');
    }
}

function userManagedMiddleware(config: ValidatedConfig) {
    return async function(req: Request, res: Response, next: NextFunction): Promise<void> {
        const shouldContinue = await commonMiddleware(req, res, config);
        if (!shouldContinue) {
            return;
        }

        if (req.path === '/verify-monocle' && req.method === 'POST') {
            console.log('Verifying Monocle captcha');
            console.log('Using user-managed decryption method');
            validateCaptchaUserManaged(req, config).then(({status, body, headers}) => {
                console.log("Status: ", status, " Body: ", body, " Headers: ", headers)
                if (headers) {
                    res.set(headers);
                }
                res.status(status).send(body);
            });
        } else {
            next();
        }
    }
}

function spurManagedMiddleware(config: ValidatedConfig) {
    return async function(req: Request, res: Response, next: NextFunction): Promise<void> {
        const shouldContinue = await commonMiddleware(req, res, config);
        if (!shouldContinue) {
            console.log('Should not continue')
            return;
        }

        if (req.path === '/verify-monocle' && req.method === 'POST') {
            console.log('Verifying Monocle captcha');
            console.log('Using spur-managed decryption method');
            validateCaptchaSpurManaged(req, config).then(({status, body, headers}) => {
                console.log("Status: ", status, " Body: ", body, " Headers: ", headers)
                if (headers) {
                    res.set(headers);
                }
                res.status(status).send(body);
            });
        } else {
            console.log('Next')
            next();
        }
    }
}

function createMclValidCookie(request: Request, secure: boolean, cookieSecret: string) {
    var clientIpAddress = getClientIpAddress(request);
    const expiryTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const cookieValue = `${clientIpAddress}|${expiryTime}`;
    const secretKey = crypto.createSecretKey(hexToBuf(cookieSecret));
    const iv = crypto.randomBytes(12); // Generate a random initialization vector
    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    const encryptedValue = Buffer.concat([cipher.update(cookieValue, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const encryptedValueHex = bufToHex(encryptedValue);
    const ivHex = bufToHex(iv);
    const authTagHex = bufToHex(authTag);
    const cookie = serialize('MCLVALID', `${ivHex}.${encryptedValueHex}.${authTagHex}`, {
        secure: secure,
        httpOnly: true,
        path: '/',
        sameSite: 'strict'
    });

    return {'Set-Cookie': cookie};
}

function validateCookie(clientIpAddress: string, mclValidCookie: string, cookieSecret: string) {
    const [ivHex, encryptedValueHex, authTagHex] = mclValidCookie.split('.');
    if (!ivHex || !encryptedValueHex || !authTagHex) {
        return false;
    }

    const secretKey = crypto.createSecretKey(hexToBuf(cookieSecret));

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
    if (clientIpAddress !== cookieClientIpAddress) {
        return false;
    }

    return Math.floor(Date.now() / 1000) < parseInt(expiryTime, 10);
}

async function commonMiddleware(req: Request, res: Response, config: ValidatedConfig): Promise<boolean> {
    const cookies = parse(req.headers['cookie'] || '');
    const mclValidCookie = cookies['MCLVALID'];
    const siteToken = config.siteToken;
    const cookieSecret = config.cookieSecret;

    if (!mclValidCookie && req.path !== '/verify-monocle' && req.path !== '/denied') {
        console.log('No MCLVALID cookie found');
        res.render(path.join(__dirname, '..', 'views', 'monocle_captcha_page'), {siteToken});
        return false;
    } else if (req.path === '/denied') {
        //  the service should be in the query string
        const service = req.query.service;
        console.log('Rendering denied page with service:', service)
        res.render(path.join(__dirname, '..', 'views', 'denied'), {service});
        return false;
    } else if (mclValidCookie) {
        const clientIpAddress = getClientIpAddress(req);
        const cookieValid = validateCookie(clientIpAddress, mclValidCookie, cookieSecret);
        if (!cookieValid) {
            // clear the cookie
            res.clearCookie('MCLVALID', {path: '/'});
            console.log('Invalid MCLVALID cookie found');
            res.render(path.join(__dirname, '..', 'views', 'monocle_captcha_page'), {siteToken});
            return false;
        }
    }

    if (req.path === '/verify-monocle' && req.method === 'POST') {
        console.log('Verifying Monocle captcha');
        return true;
    } else {
        return false;
    }
}

function validateConfig(config: MiddlewareConfig): ValidatedConfig {
    const validatedConfig = {} as ValidatedConfig;
    if (!config.siteToken) {
        throw new Error('siteToken is required');
    } else {
        validatedConfig.siteToken = config.siteToken;
    }

    if (!config.decryptionMethod) {
        throw new Error('decryptionMethod is required');
    } else {
        validatedConfig.decryptionMethod = config.decryptionMethod;
    }

    if (!config.cookieSecret) {
        throw new Error('cookieSecret is required');
    } else {
        validatedConfig.cookieSecret = config.cookieSecret;
    }

    if (!config.local) {
        validatedConfig.local = false;
    } else validatedConfig.local = config.local === 'true';

    if (config.decryptionMethod === 'user-managed') {
        if (!config.privateKey) {
            throw new Error('privateKey is required');
        } else {
            validatedConfig.privateKey = config.privateKey;
        }
    }

    if (config.decryptionMethod === 'spur-managed') {
        if (!config.verifyToken) {
            throw new Error('verifyToken is required');
        } else {
            validatedConfig.verifyToken = config.verifyToken;
        }
    }

    if (!config.nodeEnv) {
        validatedConfig.nodeEnv = 'production';
    } else {
        validatedConfig.nodeEnv = config.nodeEnv;
    }

    validatedConfig.secure = validatedConfig.nodeEnv === 'production';

    return validatedConfig;
}

async function validateCaptchaUserManaged(request: Request, config: ValidatedConfig) {
    try {
        const captchaData = request.body.captchaData;
        const privateKey = await importPKCS8(config.privateKey, "ECDH-ES");
        const decoder = new TextDecoder();
        const decryptResult = await compactDecrypt(captchaData, privateKey);
        const data = JSON.parse(decoder.decode(decryptResult.plaintext));
        const clientIpAddress = getClientIpAddress(request);
        const responseTime = new Date(data.ts);
        const currentTime = new Date();
        const timeDifference = Math.abs(currentTime.getTime() - responseTime.getTime()) / 1000;

        console.log('Local env:', config.local)
        if (config.local) {
            console.log('Local environment detected, skipping IP check');
            // @ts-ignore
            data.ip = clientIpAddress;
        } else {
            console.log('Local environment not detected, checking IP')
        }

        if (timeDifference > 5 || data.ip !== clientIpAddress || data.anon) {
            return {status: 403, body: JSON.stringify(data)};
        }

        const headers = createMclValidCookie(request, config.secure, config.cookieSecret);
        return {status: 200, body: "Captcha validated successfully", headers: headers};
    } catch (error) {
        if (error instanceof Error) {
            console.error(`Error calling third-party API: ${error.message}`);
        } else {
            console.error(`Error calling third-party API: ${error}`);
        }
        return {status: 500, body: "Internal Server Error"};
    }
}

async function validateCaptchaSpurManaged(request: Request, config: ValidatedConfig) {
    try {
        const captchaData = request.body.captchaData;
        const data = await decryptAssessment(captchaData, config.verifyToken);
        const clientIpAddress = getClientIpAddress(request)
        const responseTime = new Date(data.ts);
        const currentTime = new Date();
        const timeDifference = Math.abs(currentTime.getTime() - responseTime.getTime()) / 1000;

        console.log('Local env:', config.local)
        if (config.local) {
            console.log('Local environment detected, skipping IP check');
            // @ts-ignore
            data.ip = clientIpAddress;
        } else {
            console.log('Local environment not detected, checking IP')
        }

        if (timeDifference > 5 || data.ip !== clientIpAddress || data.anon) {
            console.log('Captcha validation failed for ip and data:', clientIpAddress, data);
            return {status: 403, body: JSON.stringify(data)};
        }

        const headers = createMclValidCookie(request, config.secure, config.cookieSecret);
        return {status: 200, body: "Captcha validated successfully", headers: headers};
    } catch (error) {
        if (error instanceof Error) {
            console.error(`Error calling third-party API: ${error.message}`);
        } else {
            console.error(`Error calling third-party API: ${error}`);
        }
        return {status: 500, body: "Internal Server Error"};
    }
}

function hexToBuf(hex: string) {
    return Buffer.from(hex, 'hex');
}

function bufToHex(buffer: Buffer) {
    return buffer.toString('hex');
}

function getClientIpAddress(request: Request): string {
    let clientIpAddress = request.headers['x-forwarded-for'] || request.ip;
    if (!clientIpAddress) {
        throw new Error('Client IP address is not available');
    }

    // if the client ip is an array, get the first element. It probably came from the x-forwarded-for header.
    if (Array.isArray(clientIpAddress)) {
        clientIpAddress = clientIpAddress[0];
    }

    // check if the ip is an IPv4-mapped IPv6 address
    if (clientIpAddress.includes('::ffff:')) {
        const ipv4Address = clientIpAddress.split(':').pop();
        if (ipv4Address) {
            clientIpAddress = ipv4Address;
        }
    }

    return clientIpAddress;
}

export default createMonocleMiddleware;