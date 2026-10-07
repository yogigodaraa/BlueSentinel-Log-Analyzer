'use client';

import { useState, useEffect } from 'react';
import { Shield, Mail, AlertTriangle, Activity } from 'lucide-react';
import StatsCard from './StatsCard';
import ThreatFeed from './ThreatFeed';
import AnalysisPanel from './AnalysisPanel';
import { getDashboardStats } from '@/lib/api';

export default function Dashboard() {
  const [selectedTab, setSelectedTab] = useState('overview');
  const [stats, setStats] = useState({
    total_emails: 0,
    threats_detected: 0,
    emails_today: 0,
    detection_rate: 0
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await getDashboardStats();
        setStats(data);
      } catch (error) {
        console.error('Failed to fetch dashboard stats:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
    // Refresh stats every 30 seconds
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">SOCShield</h1>
                <p className="text-sm text-gray-500">AI-Driven Phishing Detection</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-sm text-gray-600">AI Provider: Gemini</span>
              </div>
              <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">
                Configure
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Navigation Tabs */}
        <div className="mb-8 border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            {['overview', 'analysis', 'threats', 'settings'].map((tab) => (
              <button
                key={tab}
                onClick={() => setSelectedTab(tab)}
                className={`
                  py-4 px-1 border-b-2 font-medium text-sm capitalize
                  ${selectedTab === tab
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }
                `}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>

        {/* Overview Tab */}
        {selectedTab === 'overview' && (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <StatsCard
                title="Total Emails Scanned"
                value={loading ? "..." : stats.total_emails.toLocaleString()}
                change="+12.5%"
                icon={<Mail className="w-6 h-6 text-blue-600" />}
                trend="up"
              />
              <StatsCard
                title="Threats Detected"
                value={loading ? "..." : stats.threats_detected.toString()}
                change="+8.2%"
                icon={<AlertTriangle className="w-6 h-6 text-red-600" />}
                trend="up"
              />
              <StatsCard
                title="Detection Rate"
                value={loading ? "..." : `${(stats.detection_rate * 100).toFixed(1)}%`}
                change="+2.1%"
                icon={<Activity className="w-6 h-6 text-green-600" />}
                trend="up"
              />
              <StatsCard
                title="Emails Today"
                value={loading ? "..." : stats.emails_today.toString()}
                change="-15.3%"
                icon={<Activity className="w-6 h-6 text-purple-600" />}
                trend="up"
              />
            </div>

            {/* Charts and Feed */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <div className="bg-white rounded-lg border border-gray-200 p-6">
                  <h3 className="text-lg font-semibold mb-4">Threat Timeline</h3>
                  <div className="h-64 flex items-center justify-center text-gray-400">
                    <p>Chart visualization will appear here</p>
                  </div>
                </div>
              </div>
              
              <div className="lg:col-span-1">
                <ThreatFeed />
              </div>
            </div>
          </div>
        )}

        {/* Analysis Tab */}
        {selectedTab === 'analysis' && (
          <AnalysisPanel />
        )}

        {/* Threats Tab */}
        {selectedTab === 'threats' && (
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h3 className="text-lg font-semibold mb-4">Active Threats</h3>
            <p className="text-gray-500">Threat management interface</p>
          </div>
        )}

        {/* Settings Tab */}
        {selectedTab === 'settings' && (
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h3 className="text-lg font-semibold mb-4">Settings</h3>
            <p className="text-gray-500">Configuration options</p>
          </div>
        )}
      </main>
    </div>
  );
}
