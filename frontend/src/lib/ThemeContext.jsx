import React, { createContext, useContext, useState, useEffect } from 'react'

const STORAGE_KEY = 'sentinelai_bg_config'

export const AI_WALLPAPERS = [
  { id: 'random_ai', name: 'Random AI on Every Open', desc: 'Automatically cycles a new AI wallpaper each visit', preview: '/wallpapers/circuittree.jpg' },
  { id: 'circuittree', name: 'AI Circuit Tree & Breach Key', desc: 'Motherboard circuit tree with glowing blue data streams and glitch shards', src: '/wallpapers/circuittree.jpg', preview: '/wallpapers/circuittree.jpg' },
  { id: 'matrix', name: 'AI Cyber Ops Matrix', desc: 'Futuristic SOC operations center with cyan grid', src: '/wallpapers/matrix.jpg', preview: '/wallpapers/matrix.jpg' },
  { id: 'quantum', name: 'AI Quantum Neural Net', desc: 'Glowing violet and purple neural graph nodes', src: '/wallpapers/quantum.jpg', preview: '/wallpapers/quantum.jpg' },
  { id: 'sentinel', name: 'AI Cyber Sentinel City', desc: 'Midnight cyberpunk metropolis with holographic beacons', src: '/wallpapers/sentinel.jpg', preview: '/wallpapers/sentinel.jpg' },
  { id: 'aurora', name: 'AI Synthetic Aurora', desc: 'Cosmic emerald and sapphire cyber nebula', src: '/wallpapers/aurora.jpg', preview: '/wallpapers/aurora.jpg' },
  { id: 'obsidian', name: 'AI Obsidian Hexagon', desc: 'Minimalist honeycomb obsidian grid with pulsing cyan lines', src: '/wallpapers/obsidian.jpg', preview: '/wallpapers/obsidian.jpg' },
  { id: 'canvas_neural', name: 'Interactive Neural Canvas', desc: 'Real-time interactive particle physics canvas', preview: '/wallpapers/quantum.jpg' },
  { id: 'static_dark', name: 'Classic Vision UI Dark', desc: 'Minimalist dark obsidian gradient without imagery', preview: '' },
]

const ThemeContext = createContext(null)

export function ThemeProvider({ children }) {
  const [config, setConfig] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (saved) return JSON.parse(saved)
    } catch {}
    return {
      theme: 'static_dark', // strict minimalism default
      blur: 0,              // no blur
      opacity: 0.35,        // 35%
      isStatic: true,       // static background
      isNight: true,        // default dark mode
    }
  })

  // Resolved active wallpaper image
  const [activeWallpaper, setActiveWallpaper] = useState('/wallpapers/circuittree.jpg')

  // Sync night/day class on body
  useEffect(() => {
    const isDark = config.isNight !== false
    document.body.classList.toggle('night', isDark)
    document.body.classList.toggle('day-mode', !isDark)
    localStorage.setItem('theme', isDark ? 'dark' : 'day')
  }, [config.isNight])

  // Pick random wallpaper on mount or when theme changes
  useEffect(() => {
    const staticWallpapers = ['circuittree', 'matrix', 'quantum', 'sentinel', 'aurora', 'obsidian']

    if (config.theme === 'random_ai') {
      const randomId = staticWallpapers[Math.floor(Math.random() * staticWallpapers.length)]
      setActiveWallpaper(`/wallpapers/${randomId}.jpg`)
    } else if (staticWallpapers.includes(config.theme)) {
      setActiveWallpaper(`/wallpapers/${config.theme}.jpg`)
    } else {
      setActiveWallpaper('')
    }
  }, [config.theme])

  // Save config to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(config))
    } catch {}
  }, [config])

  const setTheme = (theme) => setConfig((prev) => ({ ...prev, theme }))
  const setBlur = (blur) => setConfig((prev) => ({ ...prev, blur }))
  const setOpacity = (opacity) => setConfig((prev) => ({ ...prev, opacity }))
  const setIsStatic = (isStatic) => setConfig((prev) => ({ ...prev, isStatic }))
  const setIsNight = (isNight) => setConfig((prev) => ({ ...prev, isNight }))
  const toggleNightMode = () => setConfig((prev) => ({ ...prev, isNight: !prev.isNight }))

  const randomizeNow = () => {
    const staticWallpapers = ['circuittree', 'matrix', 'quantum', 'sentinel', 'aurora', 'obsidian']
    const randomId = staticWallpapers[Math.floor(Math.random() * staticWallpapers.length)]
    setActiveWallpaper(`/wallpapers/${randomId}.jpg`)
  }

  return (
    <ThemeContext.Provider
      value={{
        ...config,
        activeWallpaper,
        setTheme,
        setBlur,
        setOpacity,
        setIsStatic,
        setIsNight,
        toggleNightMode,
        randomizeNow,
        wallpapers: AI_WALLPAPERS,
      }}
    >
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within a ThemeProvider')
  return ctx
}
