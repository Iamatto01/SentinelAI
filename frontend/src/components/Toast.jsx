import { createContext, useCallback, useContext, useState } from 'react';

const ToastContext = createContext(null);

export function useToast() {
  return useContext(ToastContext);
}

export default function ToastProvider({ children }) {
  const [toast, setToast] = useState(null);
  const [visible, setVisible] = useState(false);

  const show = useCallback((message) => {
    setToast(message);
    setVisible(true);
    setTimeout(() => setVisible(false), 3000);
  }, []);

  return (
    <ToastContext.Provider value={show}>
      {children}

      <div
        className={`fixed top-4 right-4 glassmorphism p-4 rounded-lg border border-white/20 z-[100] transition-transform duration-300 ${
          visible ? 'translate-x-0' : 'translate-x-[120%]'
        }`}
      >
        <div className="flex items-center space-x-3">
          <span className="text-lg">&#x2705;</span>
          <div>
            <p className="font-medium text-sm">Notification</p>
            <p className="text-sm text-gray-400">{toast}</p>
          </div>
        </div>
      </div>
    </ToastContext.Provider>
  );
}
