import axios from 'axios';

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

export async function decryptAssessment(captchaData: any, verifyToken: string): Promise<ApiResponse> {
    const thirdPartyApiUrl = 'https://decrypt.mcl.spur.us/api/v1/assessment';
    const apiResponse = await axios.post(thirdPartyApiUrl, captchaData, {
        headers: {
            'Content-Type': 'text/plain',
            'Token': verifyToken,
        },
    });

    if (apiResponse.status !== 200) {
        throw new Error(`API call failed: ${apiResponse.statusText}`);
    }

    return apiResponse.data as ApiResponse;
}