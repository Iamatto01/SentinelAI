import React, { createContext, useContext, useState, useCallback } from 'react'

const ScanContext = createContext(null)

export function ScanProvider({ children }) {
  const [currentScan, setCurrentScan] = useState(null)

  const setScanContext = useCallback((scan) => {
    setCurrentScan(scan)
  }, [])

  return (
    <ScanContext.Provider value={{ currentScan, setScanContext }}>
      {children}
    </ScanContext.Provider>
  )
}

export const useScanContext = () => useContext(ScanContext)
