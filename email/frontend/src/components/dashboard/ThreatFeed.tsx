'use client';

import { AlertTriangle, Shield, Clock } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

const mockThreats = [
  {
    id: 1,
    title: 'Phishing email from fake PayPal',
    severity: 'critical',
    time: new Date(Date.now() - 1000 * 60 * 5),
    sender: 'support@paypa1.com'
  },
  {
    id: 2,
    title: 'Suspicious login request',
    severity: 'high',
    time: new Date(Date.now() - 1000 * 60 * 15),
    sender: 'noreply@microsoft-security.xyz'
  },
  {
    id: 3,
    title: 'Invoice with malicious attachment',
    severity: 'medium',
    time: new Date(Date.now() - 1000 * 60 * 32),
    sender: 'billing@company-invoice.tk'
  },
  {
    id: 4,
    title: 'Account verification request',
    severity: 'high',
    time: new Date(Date.now() - 1000 * 60 * 45),
    sender: 'security@bankofamerica.ml'
  },
];

export default function ThreatFeed() {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Recent Threats</h3>
        <Shield className="w-5 h-5 text-gray-400" />
      </div>

      <div className="space-y-4">
        {mockThreats.map((threat) => (
          <div
            key={threat.id}
            className="flex items-start space-x-3 p-3 rounded-lg hover:bg-gray-50 cursor-pointer transition"
          >
            <div className={`
              w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0
              ${threat.severity === 'critical' ? 'bg-red-100' : ''}
              ${threat.severity === 'high' ? 'bg-orange-100' : ''}
              ${threat.severity === 'medium' ? 'bg-yellow-100' : ''}
            `}>
              <AlertTriangle className={`
                w-5 h-5
                ${threat.severity === 'critical' ? 'text-red-600' : ''}
                ${threat.severity === 'high' ? 'text-orange-600' : ''}
                ${threat.severity === 'medium' ? 'text-yellow-600' : ''}
              `} />
            </div>

            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 mb-1">
                {threat.title}
              </p>
              <p className="text-xs text-gray-500 mb-1 truncate">
                From: {threat.sender}
              </p>
              <div className="flex items-center text-xs text-gray-400">
                <Clock className="w-3 h-3 mr-1" />
                {formatDistanceToNow(threat.time, { addSuffix: true })}
              </div>
            </div>

            <div>
              <span className={`
                inline-flex items-center px-2 py-1 rounded-full text-xs font-medium
                ${threat.severity === 'critical' ? 'bg-red-100 text-red-700' : ''}
                ${threat.severity === 'high' ? 'bg-orange-100 text-orange-700' : ''}
                ${threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-700' : ''}
              `}>
                {threat.severity}
              </span>
            </div>
          </div>
        ))}
      </div>

      <button className="w-full mt-4 py-2 text-sm text-blue-600 hover:text-blue-700 font-medium">
        View All Threats →
      </button>
    </div>
  );
}
