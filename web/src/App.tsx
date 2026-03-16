import { Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { RequireAuth } from './components/RequireAuth'
import { DashboardPage } from './pages/DashboardPage'
import { CommandCenterPage } from './pages/CommandCenterPage'
import { DecisionDetailPage } from './pages/DecisionDetailPage'
import { CreateDecisionPage } from './pages/CreateDecisionPage'
import { DelegationsPage } from './pages/DelegationsPage'
import { AuditTrailPage } from './pages/AuditTrailPage'
import { ConstitutionPage } from './pages/ConstitutionPage'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { IdentityPage } from './pages/IdentityPage'
import { AgentsPage } from './pages/AgentsPage'
import { PaceWizardPage } from './pages/PaceWizardPage'
import { DevBoardPage } from './pages/DevBoardPage'
import { LiveSafePage } from './pages/LiveSafePage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route path="/" element={<CommandCenterPage />} />
        <Route path="/decisions" element={<DashboardPage />} />
        <Route path="/decisions/:id" element={<DecisionDetailPage />} />
        <Route path="/decisions/new" element={<CreateDecisionPage />} />
        <Route path="/delegations" element={<DelegationsPage />} />
        <Route path="/audit" element={<AuditTrailPage />} />
        <Route path="/constitution" element={<ConstitutionPage />} />
        <Route path="/identity" element={<IdentityPage />} />
        <Route path="/identity/pace" element={<PaceWizardPage />} />
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/dev" element={<DevBoardPage />} />
        <Route path="/applications/livesafe" element={<LiveSafePage />} />
      </Route>
    </Routes>
  )
}
