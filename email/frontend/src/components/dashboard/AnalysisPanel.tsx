'use client';

import { useState, useRef } from 'react';
import { Search, Send, Loader2, Upload, FileText } from 'lucide-react';
import { analyzeEmail } from '@/lib/api';

export default function AnalysisPanel() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [formData, setFormData] = useState({
    subject: '',
    sender: '',
    body: '',
    links: ''
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const links = formData.links
        .split('\n')
        .map(l => l.trim())
        .filter(l => l);
      
      const response = await analyzeEmail({
        subject: formData.subject,
        sender: formData.sender,
        body: formData.body,
        links
      });
      
      setResult(response);
    } catch (error) {
      console.error('Analysis failed:', error);
      alert('Analysis failed. Please check your backend connection.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadedFile(file);
    
    try {
      const text = await file.text();
      
      // Simple email parsing - extract subject, sender, and body
      const lines = text.split('\n');
      let subject = '';
      let sender = '';
      let body = '';
      let inBody = false;
      const links: string[] = [];
      
      for (const line of lines) {
        if (line.startsWith('Subject:')) {
          subject = line.replace('Subject:', '').trim();
        } else if (line.startsWith('From:')) {
          sender = line.replace('From:', '').trim();
          // Extract email from format "Name <email@domain.com>"
          const emailMatch = sender.match(/<(.+?)>/);
          if (emailMatch) {
            sender = emailMatch[1];
          }
        } else if (line.trim() === '' && !inBody && subject && sender) {
          inBody = true;
        } else if (inBody) {
          body += line + '\n';
          // Extract links from body
          const urlRegex = /(https?:\/\/[^\s]+)/g;
          const matches = line.match(urlRegex);
          if (matches) {
            links.push(...matches);
          }
        }
      }
      
      // If parsing failed, use entire content as body
      if (!subject && !sender) {
        body = text;
        subject = 'Uploaded Email';
        sender = 'unknown@example.com';
      }
      
      setFormData({
        subject: subject || 'Uploaded Email',
        sender: sender || 'unknown@example.com',
        body: body.trim(),
        links: Array.from(new Set(links)).join('\n')
      });
      
      alert('Email file loaded successfully! Click "Analyze Email" to process.');
    } catch (error) {
      console.error('File upload failed:', error);
      alert('Failed to read file. Please try again.');
    }
  };

  const handleClearFile = () => {
    setUploadedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Input Form */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center mb-4">
          <Search className="w-5 h-5 text-gray-400 mr-2" />
          <h3 className="text-lg font-semibold">Analyze Email</h3>
        </div>

        {/* File Upload Section */}
        <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center">
              <Upload className="w-5 h-5 text-blue-600 mr-2" />
              <span className="font-medium text-blue-900">Upload Email File</span>
            </div>
          </div>
          
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,.txt,.msg"
            onChange={handleFileUpload}
            className="hidden"
            id="file-upload"
          />
          
          {!uploadedFile ? (
            <label
              htmlFor="file-upload"
              className="flex items-center justify-center w-full px-4 py-3 border-2 border-dashed border-blue-300 rounded-lg cursor-pointer hover:border-blue-400 hover:bg-blue-100 transition"
            >
              <FileText className="w-5 h-5 text-blue-600 mr-2" />
              <span className="text-sm text-blue-700">
                Click to upload .eml, .txt, or .msg file
              </span>
            </label>
          ) : (
            <div className="flex items-center justify-between p-3 bg-white border border-blue-300 rounded-lg">
              <div className="flex items-center">
                <FileText className="w-5 h-5 text-blue-600 mr-2" />
                <span className="text-sm text-gray-700">{uploadedFile.name}</span>
              </div>
              <button
                type="button"
                onClick={handleClearFile}
                className="text-sm text-red-600 hover:text-red-700"
              >
                Remove
              </button>
            </div>
          )}
          
          <p className="text-xs text-gray-600 mt-2">
            Upload an email file to auto-populate the form fields below
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Subject
            </label>
            <input
              type="text"
              value={formData.subject}
              onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter email subject"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Sender Email
            </label>
            <input
              type="email"
              value={formData.sender}
              onChange={(e) => setFormData({ ...formData, sender: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="sender@example.com"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Email Body
            </label>
            <textarea
              value={formData.body}
              onChange={(e) => setFormData({ ...formData, body: e.target.value })}
              rows={6}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Paste email content here..."
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Links (one per line)
            </label>
            <textarea
              value={formData.links}
              onChange={(e) => setFormData({ ...formData, links: e.target.value })}
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="https://example.com&#10;https://suspicious-link.com"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition flex items-center justify-center disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Send className="w-4 h-4 mr-2" />
                Analyze Email
              </>
            )}
          </button>
        </form>
      </div>

      {/* Results Panel */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <h3 className="text-lg font-semibold mb-4">Analysis Results</h3>

        {!result && !loading && (
          <div className="flex items-center justify-center h-64 text-gray-400">
            <p>Submit an email to see analysis results</p>
          </div>
        )}

        {loading && (
          <div className="flex items-center justify-center h-64">
            <Loader2 className="w-8 h-8 text-blue-600 animate-spin" />
          </div>
        )}

        {result && !loading && (
          <div className="space-y-4">
            {/* Risk Assessment */}
            <div className={`
              p-4 rounded-lg border-2
              ${result.is_phishing ? 'bg-red-50 border-red-200' : 'bg-green-50 border-green-200'}
            `}>
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold">
                  {result.is_phishing ? '⚠️ Phishing Detected' : '✅ Email Appears Safe'}
                </span>
                <span className={`
                  px-3 py-1 rounded-full text-sm font-medium
                  ${result.risk_level === 'critical' ? 'bg-red-100 text-red-700' : ''}
                  ${result.risk_level === 'high' ? 'bg-orange-100 text-orange-700' : ''}
                  ${result.risk_level === 'medium' ? 'bg-yellow-100 text-yellow-700' : ''}
                  ${result.risk_level === 'low' ? 'bg-green-100 text-green-700' : ''}
                `}>
                  {result.risk_level?.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center">
                <span className="text-sm text-gray-600 mr-2">Confidence:</span>
                <div className="flex-1 bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      result.confidence > 0.7 ? 'bg-red-600' : 'bg-yellow-600'
                    }`}
                    style={{ width: `${result.confidence * 100}%` }}
                  />
                </div>
                <span className="ml-2 text-sm font-medium">
                  {(result.confidence * 100).toFixed(1)}%
                </span>
              </div>
            </div>

            {/* Explanation */}
            <div>
              <h4 className="font-semibold mb-2">AI Analysis</h4>
              <p className="text-sm text-gray-600">{result.explanation}</p>
            </div>

            {/* Indicators */}
            {result.indicators && result.indicators.length > 0 && (
              <div>
                <h4 className="font-semibold mb-2">Phishing Indicators</h4>
                <ul className="space-y-1">
                  {result.indicators.map((indicator: string, index: number) => (
                    <li key={index} className="text-sm text-gray-600 flex items-start">
                      <span className="text-red-500 mr-2">•</span>
                      {indicator}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* IOCs */}
            {result.iocs && (
              <div>
                <h4 className="font-semibold mb-2">Indicators of Compromise</h4>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>
                    <span className="text-gray-500">Domains:</span>
                    <span className="ml-2 font-medium">{result.iocs.domains?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">URLs:</span>
                    <span className="ml-2 font-medium">{result.iocs.urls?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">IPs:</span>
                    <span className="ml-2 font-medium">{result.iocs.ip_addresses?.length || 0}</span>
                  </div>
                  <div>
                    <span className="text-gray-500">Emails:</span>
                    <span className="ml-2 font-medium">{result.iocs.email_addresses?.length || 0}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Metadata */}
            <div className="pt-4 border-t border-gray-200">
              <div className="flex items-center justify-between text-xs text-gray-500">
                <span>Analysis Time: {result.analysis_duration?.toFixed(2)}s</span>
                <span>Provider: {result.ai_provider}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
