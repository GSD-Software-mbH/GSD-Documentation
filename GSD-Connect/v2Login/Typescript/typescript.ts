// for login v2
public async createv2(): Promise < string > {
    // GET Encryption Key von v2/login/key
    const keyResponse = await this.httpClient.get<IKeyResponseData>(this.netApiRoutes.loginKey());
    if(!keyResponse || !keyResponse.data || !keyResponse.data.data || !keyResponse.data.data.key) {
        throw new NetApiLoginError('Cannot retrieve encryption key from net-api');
    }
    const encryptKey = keyResponse.data.data.key;
    const loginPayload: ILoginRequestBody = {
        user: this.config.netApiConfig.userName,
        pass: this.config.netApiConfig.password,
        appNames: ['GSD-Space'],
        device: {
            deviceId: this.config.netApiConfig.deviceId,
            device: this.config.netApiConfig.device,
        },
    };
    // Login-Payload verschlüsseln
    const encryptedPayload = await this.loginHelperAES.encryptRequest(JSON.stringify(loginPayload), encryptKey);
    // POST Request an v2/login mit verschlüsseltem Payload
    const loginResponse = await this.httpClient.post(
        this.netApiRoutes.loginv2(),
        encryptedPayload,
        {
            headers: {
                'appKey': this.config.netApiConfig.appKey,
                'Content-Type': 'application/json',
                'User-Agent': this.config.netApiConfig.userAgent,
            },
        },
    );
    // entschlüsseln

    let parsedResponse: ILoginParsedResponse;
    if (typeof loginResponse.data === 'string') {
        let responseBody = loginResponse.data.trim();
        if (!responseBody.startsWith('{')) {
            responseBody = this.loginHelperAES.decryptResponse(responseBody);
        }
        parsedResponse = JSON.parse(responseBody) as ILoginParsedResponse;
    } else {
        // If it's already an object, use it directly.
        parsedResponse = loginResponse.data as ILoginParsedResponse;
    }
    if (loginResponse.status !== ResponseCodes.OK) {
        throw new NetApiLoginError('Cannot get session ID from net-api');
    }

    return parsedResponse.data.sessionId;
}

import { injectable } from 'inversify';
import { ILoginHelperAES } from './ILoginHelperAES';
import * as crypto from 'crypto';
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment

@injectable()
export class LoginHelperAES implements ILoginHelperAES {
    private readonly algorithm = 'RSA/ECB/OAEPWithSHA-256AndMGF1Padding';
    private clientPrivateKey: string | null = null;

    public async encryptAES(clearText: string, aesKey: Buffer): Promise<string> {
        // Generate a random 16-byte IV
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
        let encryptedData = cipher.update(clearText, 'utf8');
        encryptedData = Buffer.concat([encryptedData, cipher.final()]);

        return JSON.stringify({
            iv: iv.toString('base64'),
            data: encryptedData.toString('base64'),
        });
    }

    public async encryptRequest(loginPayload: string, serverPublicKeyString: string): Promise<string> {
        // Parse the server's public key from its PEM string.
        const serverPublicKey = crypto.createPublicKey(serverPublicKeyString);

        // Generate an RSA key pair
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });

        // Save the private key for later decryption.
        this.clientPrivateKey = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

        // Generate a random 256-bit AES key.
        const aesKey = crypto.randomBytes(32); // 32 bytes for AES-256

        // Encrypt the loginPayload with AES.
        const encryptedBodyJson = JSON.parse(await this.encryptAES(loginPayload, aesKey)) as { iv: string; data: string };

        // Decode the base64-encoded IV and data into Buffers.
        const encryptedBodyIv = Buffer.from(encryptedBodyJson.iv, 'base64');
        const encryptedBodyData = Buffer.from(encryptedBodyJson.data, 'base64');

        // Merge the IV and encrypted data Buffers.
        const encryptedBodyMerged = Buffer.concat([encryptedBodyIv, encryptedBodyData]);
        const encryptedBodyBase64 = encryptedBodyMerged.toString('base64');

        // Encrypt the AES key using the server's RSA public key with OAEP SHA-256 padding.
        const encryptedAesKeyBuffer = crypto.publicEncrypt(
            {
                key: serverPublicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            aesKey,
        );
        const encryptedAesKeyBase64 = encryptedAesKeyBuffer.toString('base64');

        // Export our RSA public key in PEM format.
        const clientPublicKeyPEM = publicKey.export({ type: 'spki', format: 'pem' }).toString();

        const requestBody = {
            aesKey: encryptedAesKeyBase64,
            data: encryptedBodyBase64,
            publicKey: clientPublicKeyPEM,
        };

        return JSON.stringify(requestBody);
    }

    public decryptResponse(responseBodyStr: string): string {
        if (!this.clientPrivateKey) {
            throw new Error('Client private key is not set. Cannot decrypt response.');
        }

        let encryptedAesKeyBase64: string;
        let encryptedDataBase64: string;

        if (responseBodyStr.trim().startsWith('{')) {
            const requestBody = JSON.parse(responseBodyStr) as { aesKey: string; data: string };
            encryptedAesKeyBase64 = requestBody.aesKey;
            encryptedDataBase64 = requestBody.data;
        } else {
            // Otherwise, assume the response is in pipe-delimited format.
            const parts = responseBodyStr.split('|');
            if (parts.length < 2) {
                throw new Error("Unexpected response format; missing delimiter '|'.");
            }
            encryptedAesKeyBase64 = parts[0];
            encryptedDataBase64 = parts[1];
        }

        // Decrypt the AES key using the client's private key with OAEP SHA-256 padding.
        const decryptedAesKeyBuffer = crypto.privateDecrypt(
            {
                key: this.clientPrivateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            Buffer.from(encryptedAesKeyBase64, 'base64'),
        );

        // Decode the encrypted data from base64.
        const mergedBuffer = Buffer.from(encryptedDataBase64, 'base64');
        // The IV is the first 16 bytes.
        const iv = mergedBuffer.slice(0, 16);
        // The remainder is the ciphertext.
        const ciphertext = mergedBuffer.slice(16);

        // Create a decipher to decrypt the ciphertext using AES-256-CBC.
        const decipher = crypto.createDecipheriv('aes-256-cbc', decryptedAesKeyBuffer, iv);
        let decrypted = decipher.update(ciphertext, undefined, 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }
}

 