import { Routes, Route } from "react-router-dom";
import { Sidebar } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { Scan } from "./pages/Scan";

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-cyber-bg bg-grid-pattern bg-grid">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/scan/:type" element={<Scan />} />
        </Routes>
      </main>
    </div>
  );
}
