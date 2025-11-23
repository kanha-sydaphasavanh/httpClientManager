import axios from 'axios';
import type { AxiosInstance } from 'axios';
import https from 'https';
import { Agent, fetch as undiciFetch } from 'undici';
import DigestClient from 'digest-fetch';

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';
type AuthMethod = 'API_KEY' | 'BASIC' | 'BEARER_TOKEN' | 'DIGEST';

interface LoginCredentials {
    username: string;
    password: string;
}

interface ApiKeyCredentials {
    key: string;
    apiKey: string;
}

interface BearerTokenCredentials {
    token: string;
    refreshToken?: string;
}

export interface AuthData {
    security?: AuthMethod | '';
    credentials?: LoginCredentials | ApiKeyCredentials | BearerTokenCredentials | {};
}

export interface HttpClientOptions {
    ignoreSslError?: boolean;
    headers?: Record<string, string>;
}

export class HttpClientManager {

    private apiClient: AxiosInstance;
    private digestClient: DigestClient | null = null;
    private baseUrl: string;
    private authData: AuthData;
    private httpsAgent: https.Agent;
    private undiciAgent: Agent | undefined;
    private options: HttpClientOptions;

    public constructor(_baseUrl: string, _authData: AuthData | undefined, _options: HttpClientOptions = {}) {

        this.baseUrl = _baseUrl;
        this.authData = _authData ?? {};

        this.options = {
            ignoreSslError: _options.ignoreSslError ?? false,
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json;charset=utf-8',
                ..._options.headers
            }
        }

        if (this.options.ignoreSslError) {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        }

        this.httpsAgent = new https.Agent({ rejectUnauthorized: !this.options.ignoreSslError });
        this.undiciAgent = new Agent({ connect: { rejectUnauthorized: !this.options.ignoreSslError } });

        this.apiClient = axios.create({
            baseURL: this.baseUrl,
            httpsAgent: this.httpsAgent,
            headers: {
                ...this.options.headers,
                ...this.authorization(this.authData)
            }
        });

        if (this.authData.security === 'DIGEST' && this.authData.credentials) {
            const { username, password } = this.authData.credentials as LoginCredentials;
            this.digestClient = new DigestClient(username, password, {

                algorithm: 'MD5',
                statusCode: 401,
                fetch: (url: string, options: any = {}) => {
                    return undiciFetch(url, {
                        ...options,
                        headers: {
                            ...options.headers,
                            ...this.options.headers
                        },
                        dispatcher: this.undiciAgent
                    });
                }
            });
        }
    }

    private async _request(method: HttpMethod, endpoint: string, data?: any, params: Record<string, any> = {}) {
        try {
            // Si l'authentification est de type DIGEST, utiliser digestClient
            if (this.authData.security === 'DIGEST' && this.digestClient) {
                const url = `${this.baseUrl}${endpoint}${this.formatQueryParams(params)}`;
                const options = {
                    method,
                    body: method !== 'GET' ? JSON.stringify(data) : undefined,
                };

                // console.log(`API DIGEST : ${url}`);
                const response = await this.digestClient.fetch(url, options);
                const responseData = await response.json();

                return {
                    data: responseData,
                    status: response.status,
                    statusText: response.statusText,
                    headers: response.headers,
                };
            } else {
                // Utiliser axios pour les autres types d'authentification
                const config = {
                    method,
                    params: method === 'GET' ? params : undefined,
                    data: method !== 'GET' ? data : undefined,
                };
                // console.log(`API : ${this.baseUrl}${endpoint}`);

                const response = await this.apiClient(endpoint, config);
                return response;
            }
        } catch (error: any) {
            throw error;
        }
    }

    private formatQueryParams(params: Record<string, any>): string {
        if (Object.keys(params).length === 0) return '';

        const queryString = Object.entries(params)
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
            .join('&');

        return `?${queryString}`;
    }

    public post(endpoint: string, data: any, params = {}) {
        return this._request('POST', endpoint, data, params);
    }

    public get(endpoint: string, params = {}) {
        return this._request('GET', endpoint, undefined, params);
    }

    public put(endpoint: string, data: any, params = {}) {
        return this._request('PUT', endpoint, data, params);
    }

    public delete(endpoint: string, params = {}) {
        return this._request('DELETE', endpoint, undefined, params);
    }

    private authorization(authData: AuthData): Record<string, string> {
        let authHeaders: Record<string, string> = {};

        switch (authData.security) {
            case "BASIC":
                const { username, password } = authData.credentials as LoginCredentials;
                const credentials = btoa(`${username}:${password}`);
                authHeaders['Authorization'] = `Basic ${credentials}`;
                break;
            case "API_KEY":
                const { key, apiKey } = authData.credentials as ApiKeyCredentials;
                authHeaders[key] = apiKey;
                break;
            case "BEARER_TOKEN":
                const { token } = authData.credentials as BearerTokenCredentials;
                authHeaders['Authorization'] = `Bearer ${token}`;
                break;
            // Pas besoin de case pour DIGEST car cela est géré dans _request
        }

        return authHeaders;
    }
}

