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

export interface SslError {
    ignoreSslError: boolean;
}

export class HttpClientManager {
    // private static instance: HttpClientManager;
    private apiClient: AxiosInstance;
    private digestClient: DigestClient | null = null;
    private baseUrl: string;
    private authData: AuthData;
    private ignoreSslError: SslError = { ignoreSslError: false };
    private httpsAgent: https.Agent;
    private undiciAgent: Agent | undefined;

    public constructor(baseUrl: string, authData: AuthData | undefined, _ignoreSslError: SslError = { ignoreSslError: false }) {

        this.baseUrl = baseUrl;
        this.authData = authData ?? {};
        this.ignoreSslError = _ignoreSslError;

        if (this.ignoreSslError && this.ignoreSslError.ignoreSslError) {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        }

        this.httpsAgent = new https.Agent({ rejectUnauthorized: !this.ignoreSslError.ignoreSslError });
        this.undiciAgent = new Agent({ connect: { rejectUnauthorized: !this.ignoreSslError.ignoreSslError } });



        console.log('SSL Configuration:', {
            ignoreSslError: this.ignoreSslError.ignoreSslError,
            rejectUnauthorized: !this.ignoreSslError.ignoreSslError
        });

        this.apiClient = axios.create({
            baseURL: this.baseUrl,
            httpsAgent: this.httpsAgent,
        });

        if (this.authData.security === 'DIGEST' && this.authData.credentials) {
            const { username, password } = this.authData.credentials as LoginCredentials;
            this.digestClient = new DigestClient(username, password, {
                algorithm: 'MD5',
                statusCode: 401,
                fetch: (url: string, options: any = {}) => {
                    return undiciFetch(url, {
                        ...options,
                        dispatcher: this.undiciAgent
                    });
                }
            });
        }
    }


    // public static getInstance(baseURL: string, authData?: AuthData | undefined, ignoreSslError: SslError = { ignoreSslError: false }): HttpClientManager {
    //     if (!HttpClientManager.instance) {
    //         HttpClientManager.instance = new HttpClientManager(baseURL, authData, ignoreSslError);
    //     console.log(ignoreSslError);
    //     }
    //     return HttpClientManager.instance;
    // }

    private async _request(method: HttpMethod, endpoint: string, data?: any, params: Record<string, any> = {}, customHeader: Record<any, string> = {}) {
        try {
            // Si l'authentification est de type DIGEST, utiliser digestClient
            if (this.authData.security === 'DIGEST' && this.digestClient) {
                const url = `${this.baseUrl}${endpoint}${this.formatQueryParams(params)}`;
                const options = {
                    method,
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json;charset=utf-8',
                        ...customHeader,
                    },
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
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json;charset=utf-8',
                        ...this.authorizationHeader(this.authData),
                        ...customHeader,
                    },
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

    public post(endpoint: string, data: any, params = {}, customHeader = {}) {
        return this._request('POST', endpoint, data, params, customHeader);
    }

    public get(endpoint: string, params = {}, customHeader = {}) {
        return this._request('GET', endpoint, undefined, params, customHeader);
    }

    public put(endpoint: string, data: any, params = {}, customHeader = {}) {
        return this._request('PUT', endpoint, data, params, customHeader);
    }

    public delete(endpoint: string, params = {}, customHeader = {}) {
        return this._request('DELETE', endpoint, undefined, params, customHeader);
    }

    private authorizationHeader(authData: AuthData): Record<string, string> {
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

