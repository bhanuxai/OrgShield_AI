import React, { useState } from 'react';
import DashboardLayout from './layouts/DashboardLayout';
import Overview from './pages/Overview';
import ThreatInbox from './pages/ThreatInbox';
import EmailInvestigation from './pages/EmailInvestigation';
import Analytics from './pages/Analytics';
import ForensicIntelligence from './pages/ForensicIntelligence';
import ModelEvaluation from './pages/ModelEvaluation';
import Settings from './pages/Settings';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedAlertId, setSelectedAlertId] = useState(null);

  const handleNavigateToInvestigation = (alertId) => {
    setSelectedAlertId(alertId);
    setActiveTab('investigation');
  };

  return (
    <DashboardLayout activeTab={activeTab} onSelectTab={(tab) => {
      setSelectedAlertId(null);
      setActiveTab(tab);
    }}>
      {activeTab === 'overview' && (
        <Overview onNavigateToInvestigation={handleNavigateToInvestigation} />
      )}
      {activeTab === 'inbox' && (
        <ThreatInbox onNavigateToInvestigation={handleNavigateToInvestigation} />
      )}
      {activeTab === 'investigation' && (
        <EmailInvestigation initialAlertId={selectedAlertId} />
      )}
      {activeTab === 'analytics' && (
        <Analytics />
      )}
      {activeTab === 'forensics' && (
        <ForensicIntelligence />
      )}
      {activeTab === 'evaluation' && (
        <ModelEvaluation />
      )}
      {activeTab === 'settings' && (
        <Settings />
      )}
    </DashboardLayout>
  );
}
