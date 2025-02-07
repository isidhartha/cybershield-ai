/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0a0f1e",
          surface: "#0f172a",
          card: "#1e293b",
          border: "#334155",
          accent: "#f97316",
          "accent-dim": "#ea580c",
          red: "#ef4444",
          orange: "#f97316",
          yellow: "#eab308",
          green: "#22c55e",
          blue: "#38bdf8",
          purple: "#a855f7",
          muted: "#64748b",
          text: "#e2e8f0",
          "text-dim": "#94a3b8",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Cascadia Code", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanLine 2s linear infinite",
      },
      keyframes: {
        scanLine: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
      },
      backgroundImage: {
        "grid-pattern":
          "linear-gradient(rgba(249,115,22,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(249,115,22,0.05) 1px, transparent 1px)",
      },
      backgroundSize: {
        grid: "32px 32px",
      },
    },
  },
  plugins: [],
};
