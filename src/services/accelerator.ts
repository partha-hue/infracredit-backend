import axios from 'axios';
import http from 'http';

// Use Render's internal service URL or fallback to localhost for development
const ACCELERATOR_URL = process.env.ACCELERATOR_URL || 'http://localhost:18080';

const agent = new http.Agent({ 
    keepAlive: true, 
    maxSockets: 100,
    timeout: 1000 
});

const client = axios.create({
    baseURL: ACCELERATOR_URL,
    httpAgent: agent,
    timeout: 300 // Strict timeout for high-performance calls
});

export const computeOptimized = async (id: string, payload: number[]) => {
    try {
        const response = await client.post('/v1/compute', { cid: id, metrics: payload });
        return response.data;
    } catch (error) {
        console.error('Accelerator unavailable, falling back to TS logic');
        // Return baseline calculation if C++ service is down or timing out
        return {
            score: payload.reduce((a, b) => a + b, 0),
            status: 'fallback'
        };
    }
};
