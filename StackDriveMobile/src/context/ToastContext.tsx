import React, { createContext, useContext, useState, useCallback } from 'react';
import { View, Text, StyleSheet, Animated, TouchableOpacity, Platform, StatusBar } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, borderRadius, spacing, fontSizes } from '../theme/colors';

type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: number;
  message: string;
  type: ToastType;
}

interface ToastContextType {
  addToast: (message: string, type?: ToastType, duration?: number) => number;
  removeToast: (id: number) => void;
}

const ToastContext = createContext<ToastContextType>({
  addToast: () => 0,
  removeToast: () => {},
});

let toastId = 0;

const toastColors: Record<ToastType, { bg: string; border: string; icon: string }> = {
  success: { bg: '#0d1527', border: colors.safe, icon: 'checkmark-circle' },
  error: { bg: '#0d1527', border: colors.threat, icon: 'alert-circle' },
  warning: { bg: '#0d1527', border: colors.queue, icon: 'warning' },
  info: { bg: '#0d1527', border: colors.scan, icon: 'information-circle' },
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((message: string, type: ToastType = 'info', duration = 4000) => {
    const id = ++toastId;
    setToasts(prev => [...prev, { id, message, type }]);

    if (duration > 0) {
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id));
      }, duration);
    }
    return id;
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      <View style={styles.container} pointerEvents="box-none">
        {toasts.map(toast => {
          const config = toastColors[toast.type];
          return (
            <View
              key={toast.id}
              style={[styles.toast, { backgroundColor: config.bg, borderLeftColor: config.border }]}
            >
              <Ionicons name={config.icon as any} size={18} color={config.border} />
              <Text style={styles.message} numberOfLines={3}>{toast.message}</Text>
              <TouchableOpacity onPress={() => removeToast(toast.id)} hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}>
                <Ionicons name="close" size={16} color={colors.textSecondary} />
              </TouchableOpacity>
            </View>
          );
        })}
      </View>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

const styles = StyleSheet.create({
  container: {
    position: 'absolute',
    top: Platform.OS === 'ios' ? 75 : (StatusBar.currentHeight || 0) + 75,
    left: spacing.lg,
    right: spacing.lg,
    zIndex: 9999,
  },
  toast: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    padding: spacing.md,
    marginBottom: spacing.sm,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.08)',
    borderLeftWidth: 4,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
    elevation: 8,
  },
  message: {
    flex: 1,
    color: colors.textPrimary,
    fontSize: fontSizes.sm,
    fontFamily: 'monospace',
  },
});
