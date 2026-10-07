import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface EmailAnalysisRequest {
  subject: string;
  sender: string;
  recipient?: string;
  body: string;
  body_html?: string;
  links?: string[];
  attachments?: any[];
}

export interface AnalysisResponse {
  is_phishing: boolean;
  confidence: number;
  risk_level: string;
  indicators: string[];
  explanation: string;
  iocs: {
    domains: string[];
    urls: string[];
    ip_addresses: string[];
    email_addresses: string[];
    file_hashes: string[];
  };
  url_analysis: any[];
  analysis_duration: number;
  analyzed_at: string;
  ai_provider: string;
}

export const analyzeEmail = async (data: EmailAnalysisRequest): Promise<AnalysisResponse> => {
  const response = await api.post('/analysis/analyze', data);
  return response.data;
};

export const getDashboardStats = async () => {
  const response = await api.get('/dashboard/stats');
  return response.data;
};

export const getThreats = async () => {
  const response = await api.get('/threats');
  return response.data;
};

export const getEmails = async () => {
  const response = await api.get('/emails');
  return response.data;
};

export default api;
