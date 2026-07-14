import { createContext, useCallback, useContext, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const ToastContext = createContext(null);

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  return useContext(ToastContext);
}

export default function ToastProvider({ children }) {
  const [toast, setToast] = useState(null);
  const [toastType, setToastType] = useState('success');
  const [visible, setVisible] = useState(false);

  const show = useCallback((message, type = 'success') => {
    setToast(message);
    setToastType(type);
    setVisible(true);
    setTimeout(() => setVisible(false), 3000);
  }, []);

  // Create a callable function that also has .success/.error/.info/.warning methods
  // This ensures backward compatibility: toast('msg') and toast.success('msg') both work
  const toastFn = useCallback((msg) => show(msg, 'success'), [show]);
  toastFn.success = useCallback((msg) => show(msg, 'success'), [show]);
  toastFn.error = useCallback((msg) => show(msg, 'error'), [show]);
  toastFn.info = useCallback((msg) => show(msg, 'info'), [show]);
  toastFn.warning = useCallback((msg) => show(msg, 'warning'), [show]);

  return (
    <ToastContext.Provider value={toastFn}>
      {children}

      <AnimatePresence>
        {visible && (
          <motion.div
            initial={{ opacity: 0, x: 100, scale: 0.9 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 100, scale: 0.9 }}
            transition={{ type: 'spring', damping: 20, stiffness: 300 }}
            className={`fixed top-4 right-4 p-4 rounded-2xl border z-[100] shadow-xl backdrop-blur-md ${
              toastType === 'error' ? 'bg-red-950/80 border-red-500/30 text-white' : 
              toastType === 'warning' ? 'bg-amber-950/80 border-amber-500/30 text-white' : 
              toastType === 'info' ? 'bg-blue-950/80 border-blue-500/30 text-white' : 
              'bg-emerald-950/80 border-emerald-500/30 text-white'
            }`}
          >
            <div className="flex items-center space-x-3">
              <motion.span 
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.1, type: 'spring', stiffness: 500 }}
                className="text-lg"
              >
                {toastType === 'error' ? '❌' : toastType === 'warning' ? '⚠️' : toastType === 'info' ? 'ℹ️' : '✅'}
              </motion.span>
              <div>
                <p className="font-medium text-sm capitalize">{toastType}</p>
                <p className="text-sm opacity-90">{toast}</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </ToastContext.Provider>
  );
}
