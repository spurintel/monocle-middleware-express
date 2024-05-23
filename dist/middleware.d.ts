/// <reference types="qs" />
/// <reference types="cookie-parser" />
import { Request, Response, NextFunction } from 'express';
interface MiddlewareConfig {
    siteToken: string | undefined;
    decryptionMethod: string | undefined;
    cookieSecret: string | undefined;
    privateKey: string | undefined;
    local: string | undefined;
    verifyToken: string | undefined;
    nodeEnv: string | undefined;
}
declare function createMonocleMiddleware(config: MiddlewareConfig): (req: Request<import("express-serve-static-core").ParamsDictionary, any, any, import("qs").ParsedQs, Record<string, any>>, res: Response<any, Record<string, any>>, next: NextFunction) => Promise<void>;
export default createMonocleMiddleware;
