import { Settings, User, Bell, Shield, Palette, Globe } from 'lucide-react'
import AppLayout from '../components/layout/AppLayout'
import { useAuth } from '../context/AuthContext'

const SETTING_SECTIONS = [
  {
    id: 'profile',
    icon: User,
    title: 'Profile',
    description: 'Manage your account information',
    fields: [
      { label: 'Full Name', type: 'text', placeholder: 'John Doe', disabled: false },
      { label: 'Email', type: 'email', placeholder: 'analyst@sentinelx.ai', disabled: true },
    ],
  },
  {
    id: 'security',
    icon: Shield,
    title: 'Security',
    description: 'Password and authentication settings',
    fields: [
      { label: 'Current Password', type: 'password', placeholder: '••••••••', disabled: false },
      { label: 'New Password', type: 'password', placeholder: '••••••••', disabled: false },
    ],
  },
  {
    id: 'notifications',
    icon: Bell,
    title: 'Notifications',
    description: 'Configure alert preferences',
    toggles: [
      { label: 'Email alerts for critical incidents', enabled: true },
      { label: 'Slack notifications', enabled: false },
      { label: 'Weekly digest report', enabled: true },
    ],
  },
  {
    id: 'appearance',
    icon: Palette,
    title: 'Appearance',
    description: 'Theme and display preferences',
    toggles: [
      { label: 'Dark mode', enabled: true, locked: true },
      { label: 'Compact sidebar', enabled: false },
      { label: 'Show metric trends', enabled: true },
    ],
  },
]

export default function SettingsPage() {
  const { user } = useAuth()

  return (
    <AppLayout>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
          <Settings className="w-6 h-6 text-cyan-400" />
          Settings
        </h1>
        <p className="text-sm text-slate-500 mt-1">Manage your platform preferences</p>
      </div>

      <div className="space-y-6 max-w-2xl">
        {SETTING_SECTIONS.map(({ id, icon: Icon, title, description, fields, toggles }) => (
          <div key={id} className="glass-card p-6">
            <div className="flex items-start gap-3 mb-5">
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20
                              flex items-center justify-center flex-shrink-0">
                <Icon className="w-4 h-4 text-cyan-400" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
                <p className="text-xs text-slate-500">{description}</p>
              </div>
            </div>

            {fields && (
              <div className="space-y-4">
                {fields.map((field) => (
                  <div key={field.label}>
                    <label className="input-label">{field.label}</label>
                    <input
                      type={field.type}
                      placeholder={field.placeholder}
                      disabled={field.disabled}
                      defaultValue={field.label === 'Email' ? user?.email : ''}
                      className="input-field disabled:opacity-50 disabled:cursor-not-allowed"
                    />
                  </div>
                ))}
                <button className="btn-primary mt-2">Save {title}</button>
              </div>
            )}

            {toggles && (
              <div className="space-y-3">
                {toggles.map((toggle) => (
                  <div key={toggle.label}
                       className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
                    <span className="text-sm text-slate-300">{toggle.label}</span>
                    <button
                      className={`relative w-11 h-6 rounded-full transition-colors
                                  ${toggle.enabled ? 'bg-cyan-500' : 'bg-white/10'}
                                  ${toggle.locked ? 'opacity-50 cursor-not-allowed' : ''}`}
                      disabled={toggle.locked}
                    >
                      <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform
                                        ${toggle.enabled ? 'left-6' : 'left-1'}`} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}

        {/* Version info */}
        <div className="flex items-center gap-2 text-xs text-slate-600 px-1">
          <Globe className="w-3 h-3" />
          SentinelX AI v1.0.0 — Phase 1 (Infrastructure)
        </div>
      </div>
    </AppLayout>
  )
}
