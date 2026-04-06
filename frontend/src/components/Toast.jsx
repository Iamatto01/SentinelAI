import { createContext, useCallback, useContext, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

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

      <AnimatePresence>
        {visible && (
          <motion.div
            initial={{ opacity: 0, x: 100, scale: 0.9 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 100, scale: 0.9 }}
            transition={{ type: 'spring', damping: 20, stiffness: 300 }}
            className="fixed top-4 right-4 glassmorphism p-4 rounded-2xl border border-white/20 z-[100] shadow-xl"
          >
            <div className="flex items-center space-x-3">
              <motion.span 
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.1, type: 'spring', stiffness: 500 }}
                className="text-lg"
              >
                ✅
              </motion.span>
              <div>
                <p className="font-medium text-sm">Notification</p>
                <p className="text-sm text-gray-400">{toast}</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </ToastContext.Provider>
  );
}
