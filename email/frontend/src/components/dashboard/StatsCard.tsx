'use client';

import { ArrowUp, ArrowDown } from 'lucide-react';

interface StatsCardProps {
  title: string;
  value: string;
  change: string;
  icon: React.ReactNode;
  trend: 'up' | 'down';
}

export default function StatsCard({ title, value, change, icon, trend }: StatsCardProps) {
  const isPositive = trend === 'up' && change.startsWith('+');
  const isNegative = trend === 'up' && change.startsWith('-');

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600 mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>
          <div className="flex items-center mt-2">
            {trend === 'up' ? (
              <ArrowUp className={`w-4 h-4 ${isPositive ? 'text-green-600' : 'text-red-600'}`} />
            ) : (
              <ArrowDown className={`w-4 h-4 ${isNegative ? 'text-red-600' : 'text-green-600'}`} />
            )}
            <span className={`text-sm font-medium ml-1 ${
              (isPositive || (trend === 'down' && change.startsWith('-')))
                ? 'text-green-600'
                : 'text-red-600'
            }`}>
              {change}
            </span>
            <span className="text-sm text-gray-500 ml-1">vs last week</span>
          </div>
        </div>
        <div className="ml-4">
          {icon}
        </div>
      </div>
    </div>
  );
}
