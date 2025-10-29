import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default_32_character_key_123456789';
const ALGORITHM = 'aes-256-cbc';

export function encryptText(text) {
    if (!text) return null;

    try {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(ALGORITHM, ENCRYPTION_KEY);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return {
            encrypted,
            iv: iv.toString('hex')
        };
    } catch (error) {
        console.error('Encryption error:', error);
        return null;
    }
}

export function decryptText(encryptedData) {
    if (!encryptedData || !encryptedData.encrypted) return null;

    try {
        const decipher = crypto.createDecipher(ALGORITHM, ENCRYPTION_KEY);

        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}