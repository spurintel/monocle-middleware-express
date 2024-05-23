export interface ApiResponse {
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
export declare function decryptAssessment(captchaData: any, verifyToken: string): Promise<ApiResponse>;
