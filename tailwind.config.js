/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./finbot/**/*.html",
    "./finbot/**/*.js",
    "./finbot/static/pages/**/*.html",
  ],
  theme: {
    extend: {
      colors: {
        // ── Vendor Portal ──────────────────────────────────────────
        'vendor-primary': '#00d4ff',
        'vendor-secondary': '#7c3aed',
        'vendor-accent': '#06ffa5',
        'vendor-warning': '#ffb800',
        'vendor-danger': '#ff3366',

        // ── Admin Portal ───────────────────────────────────────────
        'admin-primary': '#f59e0b',
        'admin-secondary': '#d97706',
        'admin-accent': '#fbbf24',
        'admin-danger': '#ef4444',
        'admin-success': '#22c55e',

        // ── CTF Portal ─────────────────────────────────────────────
        'ctf-primary': '#00d4ff',
        'ctf-secondary': '#7c3aed',
        'ctf-accent': '#06ffa5',
        'ctf-warning': '#ffb800',
        'ctf-danger': '#ff3366',

        // ── Web / CineFlow ─────────────────────────────────────────
        'cine-gold': '#D4AF37',
        'cine-dark': '#0F0F0F',
        'cine-gray': '#1A1A1A',
        'cine-light': '#F8F8F8',
        'ctf-green': '#10B981',
        'ctf-dark': '#111827',
        'ctf-gray': '#374151',

        // ── FinBot / Agreement / Finbot pages ──────────────────────
        'cyan': '#00d4ff',
        'purple': '#7c3aed',
        'green': '#06ffa5',
        'amber': '#ffb800',
        'danger': '#ff3366',

        // ── CC (Command Center) ────────────────────────────────────
        'cc-surface': 'rgba(255,255,255,0.03)',
        'cc-border': 'rgba(255,255,255,0.07)',

        // ── Shared Portal Backgrounds ──────────────────────────────
        'portal-bg-primary': '#0a0a0f',
        'portal-bg-secondary': '#151520',
        'portal-bg-tertiary': '#1a1a2e',
        'portal-surface': '#1e1e2e',

        // ── Text ───────────────────────────────────────────────────
        'text-primary': '#e2e8f0',
        'text-secondary': '#94a3b8',
        'text-bright': '#ffffff',

        // ── Finbot page tokens ────────────────────────────────────
        'bg-primary': '#07070d',
        'text-1': '#f1f5f9',
        'text-2': '#94a3b8',
        'text-3': '#475569',
        'border-dim': 'rgba(255,255,255,0.06)',
        'border-glow': 'rgba(0,212,255,0.35)',
      },
      fontFamily: {
        'sans': ['Inter', 'system-ui', 'sans-serif'],
        'mono': ['JetBrains Mono', 'monospace'],
        'display': ['Playfair Display', 'serif'],
      },
      animation: {
        'fade-in': 'fadeIn 0.6s ease-out',
        'slide-up': 'slideUp 0.6s ease-out',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'float': 'float 6s ease-in-out infinite',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite alternate',
      },
      zIndex: {
        '60': '60',
        '70': '70',
      },
    },
  },
  plugins: [],
}
