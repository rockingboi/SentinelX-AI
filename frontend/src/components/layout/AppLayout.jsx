import Sidebar from './Sidebar'
import Navbar from './Navbar'

export default function AppLayout({ children, onRefresh, refreshing }) {
  return (
    <div className="flex h-screen overflow-hidden bg-sentinel-950 bg-grid-pattern">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Navbar onRefresh={onRefresh} refreshing={refreshing} />
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto animate-slide-up">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}
