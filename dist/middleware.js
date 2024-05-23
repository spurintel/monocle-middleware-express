"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const cookie_1 = require("cookie");
const jose_1 = require("jose");
const util_1 = require("util");
const path_1 = __importDefault(require("path"));
const spur_1 = require("./spur");
function createMonocleMiddleware(config) {
    const validatedConfig = validateConfig(config);
    if (config.decryptionMethod === 'user-managed') {
        return userManagedMiddleware(validatedConfig);
    }
    else if (config.decryptionMethod === 'spur-managed') {
        return spurManagedMiddleware(validatedConfig);
    }
    else {
        throw new Error('Invalid decryption method');
    }
}
function userManagedMiddleware(config) {
    return function (req, res, next) {
        return __awaiter(this, void 0, void 0, function* () {
            const shouldContinue = yield commonMiddleware(req, res, config);
            if (!shouldContinue) {
                console.log('Should not continue');
                return;
            }
            if (req.path === '/verify-monocle' && req.method === 'POST') {
                console.log('Verifying Monocle captcha');
                console.log('Using user-managed decryption method');
                validateCaptchaUserManaged(req, config).then(({ status, body, headers }) => {
                    console.log("Status: ", status, " Body: ", body, " Headers: ", headers);
                    if (headers) {
                        res.set(headers);
                    }
                    res.status(status).send(body);
                });
            }
            else {
                console.log('Next');
                next();
            }
        });
    };
}
function spurManagedMiddleware(config) {
    return function (req, res, next) {
        return __awaiter(this, void 0, void 0, function* () {
            const shouldContinue = yield commonMiddleware(req, res, config);
            if (!shouldContinue) {
                console.log('Should not continue');
                return;
            }
            if (req.path === '/verify-monocle' && req.method === 'POST') {
                console.log('Verifying Monocle captcha');
                console.log('Using spur-managed decryption method');
                validateCaptchaSpurManaged(req, config).then(({ status, body, headers }) => {
                    console.log("Status: ", status, " Body: ", body, " Headers: ", headers);
                    if (headers) {
                        res.set(headers);
                    }
                    res.status(status).send(body);
                });
            }
            else {
                console.log('Next');
                next();
            }
        });
    };
}
function createMclValidCookie(request, secure, cookieSecret) {
    var clientIpAddress = getClientIpAddress(request);
    const expiryTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const cookieValue = `${clientIpAddress}|${expiryTime}`;
    const secretKey = crypto_1.default.createSecretKey(hexToBuf(cookieSecret));
    const iv = crypto_1.default.randomBytes(12); // Generate a random initialization vector
    const cipher = crypto_1.default.createCipheriv('aes-256-gcm', secretKey, iv);
    const encryptedValue = Buffer.concat([cipher.update(cookieValue, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const encryptedValueHex = bufToHex(encryptedValue);
    const ivHex = bufToHex(iv);
    const authTagHex = bufToHex(authTag);
    const cookie = (0, cookie_1.serialize)('MCLVALID', `${ivHex}.${encryptedValueHex}.${authTagHex}`, {
        secure: secure,
        httpOnly: true,
        path: '/',
        sameSite: 'strict'
    });
    return { 'Set-Cookie': cookie };
}
function validateCookie(clientIpAddress, mclValidCookie, cookieSecret) {
    const [ivHex, encryptedValueHex, authTagHex] = mclValidCookie.split('.');
    if (!ivHex || !encryptedValueHex || !authTagHex) {
        return false;
    }
    const secretKey = crypto_1.default.createSecretKey(hexToBuf(cookieSecret));
    const decipher = crypto_1.default.createDecipheriv('aes-256-gcm', secretKey, hexToBuf(ivHex));
    decipher.setAuthTag(hexToBuf(authTagHex));
    let decryptedValue;
    try {
        decryptedValue = decipher.update(encryptedValueHex, 'hex', 'utf8') + decipher.final('utf8');
    }
    catch (err) {
        console.error('Failed to decrypt:', err);
        return false;
    }
    const [cookieClientIpAddress, expiryTime] = decryptedValue.split('|');
    if (clientIpAddress !== cookieClientIpAddress) {
        return false;
    }
    return Math.floor(Date.now() / 1000) < parseInt(expiryTime, 10);
}
function commonMiddleware(req, res, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const cookies = (0, cookie_1.parse)(req.headers['cookie'] || '');
        const mclValidCookie = cookies['MCLVALID'];
        const siteToken = config.siteToken;
        const cookieSecret = config.cookieSecret;
        if (!mclValidCookie && req.path !== '/verify-monocle' && req.path !== '/denied') {
            console.log('No MCLVALID cookie found');
            res.render(path_1.default.join(__dirname, '..', 'views', 'monocle_captcha_page'), { siteToken });
            return false;
        }
        else if (req.path === '/denied') {
            //  the service should be in the query string
            const service = req.query.service;
            console.log('Rendering denied page with service:', service);
            res.render(path_1.default.join(__dirname, '..', 'views', 'denied'), { service });
            return false;
        }
        else if (mclValidCookie) {
            const clientIpAddress = getClientIpAddress(req);
            const cookieValid = validateCookie(clientIpAddress, mclValidCookie, cookieSecret);
            if (!cookieValid) {
                // clear the cookie
                res.clearCookie('MCLVALID', { path: '/' });
                console.log('Invalid MCLVALID cookie found');
                res.render(path_1.default.join(__dirname, '..', 'views', 'monocle_captcha_page'), { siteToken });
                return false;
            }
        }
        return true;
    });
}
function validateConfig(config) {
    const validatedConfig = {};
    if (!config.siteToken) {
        throw new Error('siteToken is required');
    }
    else {
        validatedConfig.siteToken = config.siteToken;
    }
    if (!config.decryptionMethod) {
        throw new Error('decryptionMethod is required');
    }
    else {
        validatedConfig.decryptionMethod = config.decryptionMethod;
    }
    if (!config.cookieSecret) {
        throw new Error('cookieSecret is required');
    }
    else {
        validatedConfig.cookieSecret = config.cookieSecret;
    }
    if (!config.local) {
        validatedConfig.local = false;
    }
    else
        validatedConfig.local = config.local === 'true';
    if (config.decryptionMethod === 'user-managed') {
        if (!config.privateKey) {
            throw new Error('privateKey is required');
        }
        else {
            validatedConfig.privateKey = config.privateKey;
        }
    }
    if (config.decryptionMethod === 'spur-managed') {
        if (!config.verifyToken) {
            throw new Error('verifyToken is required');
        }
        else {
            validatedConfig.verifyToken = config.verifyToken;
        }
    }
    if (!config.nodeEnv) {
        validatedConfig.nodeEnv = 'production';
    }
    else {
        validatedConfig.nodeEnv = config.nodeEnv;
    }
    validatedConfig.secure = validatedConfig.nodeEnv === 'production';
    return validatedConfig;
}
function validateCaptchaUserManaged(request, config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const captchaData = request.body.captchaData;
            const privateKey = yield (0, jose_1.importPKCS8)(config.privateKey, "ECDH-ES");
            const decoder = new util_1.TextDecoder();
            const decryptResult = yield (0, jose_1.compactDecrypt)(captchaData, privateKey);
            const data = JSON.parse(decoder.decode(decryptResult.plaintext));
            const clientIpAddress = getClientIpAddress(request);
            const responseTime = new Date(data.ts);
            const currentTime = new Date();
            const timeDifference = Math.abs(currentTime.getTime() - responseTime.getTime()) / 1000;
            console.log('Local env:', config.local);
            if (config.local) {
                console.log('Local environment detected, skipping IP check');
                // @ts-ignore
                data.ip = clientIpAddress;
            }
            else {
                console.log('Local environment not detected, checking IP');
            }
            if (timeDifference > 5 || data.ip !== clientIpAddress || data.anon) {
                return { status: 403, body: JSON.stringify(data) };
            }
            const headers = createMclValidCookie(request, config.secure, config.cookieSecret);
            return { status: 200, body: "Captcha validated successfully", headers: headers };
        }
        catch (error) {
            if (error instanceof Error) {
                console.error(`Error calling third-party API: ${error.message}`);
            }
            else {
                console.error(`Error calling third-party API: ${error}`);
            }
            return { status: 500, body: "Internal Server Error" };
        }
    });
}
function validateCaptchaSpurManaged(request, config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const captchaData = request.body.captchaData;
            const data = yield (0, spur_1.decryptAssessment)(captchaData, config.verifyToken);
            const clientIpAddress = getClientIpAddress(request);
            const responseTime = new Date(data.ts);
            const currentTime = new Date();
            const timeDifference = Math.abs(currentTime.getTime() - responseTime.getTime()) / 1000;
            console.log('Local env:', config.local);
            if (config.local) {
                console.log('Local environment detected, skipping IP check');
                // @ts-ignore
                data.ip = clientIpAddress;
            }
            else {
                console.log('Local environment not detected, checking IP');
            }
            if (timeDifference > 5 || data.ip !== clientIpAddress || data.anon) {
                console.log('Captcha validation failed for ip and data:', clientIpAddress, data);
                return { status: 403, body: JSON.stringify(data) };
            }
            const headers = createMclValidCookie(request, config.secure, config.cookieSecret);
            return { status: 200, body: "Captcha validated successfully", headers: headers };
        }
        catch (error) {
            if (error instanceof Error) {
                console.error(`Error calling third-party API: ${error.message}`);
            }
            else {
                console.error(`Error calling third-party API: ${error}`);
            }
            return { status: 500, body: "Internal Server Error" };
        }
    });
}
function hexToBuf(hex) {
    return Buffer.from(hex, 'hex');
}
function bufToHex(buffer) {
    return buffer.toString('hex');
}
function getClientIpAddress(request) {
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
exports.default = createMonocleMiddleware;
