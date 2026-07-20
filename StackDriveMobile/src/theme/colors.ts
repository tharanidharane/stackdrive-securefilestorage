/**
 * StackDrive Mobile Design System
 * Mirrors the web CSS custom properties for a consistent look
 */

export const colors = {
  // Backgrounds
  bgDeep: '#0B0F19',
  bgBase: '#0D1117',
  bgSurface: '#131A27',
  bgElevated: '#1A2336',
  bgBorder: '#1E2D42',
  bgSidebar: '#0F1623',

  // Status Colors
  safe: '#22C55E',
  threat: '#EF4444',
  queue: '#F59E0B',
  scan: '#3B82F6',
  pass: '#06B6D4',

  // Badge Backgrounds
  badgeSafe: '#15803D',
  badgeThreat: '#991B1B',
  badgeQueue: '#92400E',
  badgeScan: '#1D4ED8',
  badgePass: '#164E63',

  // Text
  textPrimary: '#F1F5F9',
  textSecondary: '#94A3B8',
  textMuted: '#475569',
  textAccent: '#38BDF8',

  // Brand
  brandGreen: '#4ADE80',
  accent: '#3B82F6',
  accentHover: '#4B91F7',

  // Utility
  white: '#FFFFFF',
  black: '#000000',
  transparent: 'transparent',

  // Status-specific
  successBg: 'rgba(16, 185, 129, 0.1)',
  successBorder: 'rgba(16, 185, 129, 0.3)',
  threatBg: 'rgba(239, 68, 68, 0.1)',
  threatBorder: 'rgba(239, 68, 68, 0.2)',
  shareBg: 'rgba(59, 130, 246, 0.1)',
  shareBorder: 'rgba(59, 130, 246, 0.2)',
};

export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  '2xl': 24,
  '3xl': 32,
  '4xl': 48,
};

export const borderRadius = {
  sm: 4,
  md: 8,
  lg: 12,
  xl: 16,
  full: 9999,
};

export const fontSizes = {
  '6xl': 48,
  '4xl': 36,
  '2xl': 24,
  xl: 20,
  lg: 18,
  base: 16,
  sm: 14,
  xs: 12,
  '2xs': 10,
};

export const fonts = {
  mono: 'monospace',  // Platform.select({ ios: 'Courier', android: 'monospace' })
};
