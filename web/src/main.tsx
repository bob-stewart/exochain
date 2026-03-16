import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from './lib/auth'
import { CouncilProvider } from './lib/CouncilContext'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <CouncilProvider>
          <App />
        </CouncilProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
