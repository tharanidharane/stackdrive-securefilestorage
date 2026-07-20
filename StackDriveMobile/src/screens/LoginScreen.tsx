import React, { useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView,
  KeyboardAvoidingView, Platform, ActivityIndicator, Dimensions,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import api from '../services/api';
import EncryptionScene from '../components/EncryptionScene';

const { width } = Dimensions.get('window');

interface LoginScreenProps {
  onLogin: (user: any) => void;
  onNavigateSignup: () => void;
  onNavigateForgot: () => void;
}

export default function LoginScreen({ onLogin, onNavigateSignup, onNavigateForgot }: LoginScreenProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<any>({});
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [lastLoginInfo, setLastLoginInfo] = useState('');
  const { addToast } = useToast();



  const validateForm = () => {
    const errs: any = {};
    if (!email) errs.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(email)) errs.email = 'Enter a valid email';
    if (!password) errs.password = 'Password is required';
    else if (password.length < 6) errs.password = 'Minimum 6 characters';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleLogin = async () => {
    if (!validateForm()) return;
    setLoading(true);
    try {
      const loginData = await api.login(email, password);

      // Format last login info if available
      if (loginData.user && loginData.user.last_login_at) {
        const dateStr = new Date(loginData.user.last_login_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
        setLastLoginInfo(`Last signed in from ${loginData.user.last_login_device || 'Unknown'} at ${dateStr}`);
      } else {
        setLastLoginInfo('First login to StackDrive');
      }

      // Play cinematic unlock
      setIsUnlocking(true);

      setTimeout(() => {
        addToast('Welcome to StackDrive!', 'success');
        onLogin(loginData.user);
      }, 2500);

    } catch (err: any) {
      if (err.status === 401) {
        setErrors({ password: err.message || 'Incorrect password' });
      } else if (err.status === 404) {
        setErrors({ email: 'No account found with this email' });
      } else {
        addToast(err.message || 'Login failed', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={styles.container}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.keyboardView}
      >
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
          keyboardShouldPersistTaps="handled"
        >
          {/* Padlock and Orbit Scene */}
          <EncryptionScene isUnlocking={isUnlocking} />

          {/* Logo */}
          <View style={styles.logoSection}>
            <Text style={styles.logoText}>StackDrive</Text>
            <Text style={styles.logoSubtext}>Quantum-Safe File Gateway</Text>
          </View>

          {/* Card */}
          <View style={styles.card}>
            {isUnlocking ? (
              <View style={styles.unlockingWrap}>
                <Text style={styles.cardTitle}>Unlocking Gateway...</Text>
                <ActivityIndicator size="large" color={colors.accent} style={{ marginVertical: spacing.xl }} />
                {lastLoginInfo ? (
                  <Text style={styles.lastLoginText}>{lastLoginInfo}</Text>
                ) : null}
              </View>
            ) : (
              <>
                <Text style={styles.cardTitle}>Welcome Back</Text>
                <Text style={styles.cardSubtitle}>Sign in to your secure file gateway</Text>

                {/* Email */}
                <View style={styles.inputGroup}>
                  <Text style={styles.label}>EMAIL ADDRESS</Text>
                  <View style={[styles.inputWrapper, errors.email && styles.inputError]}>
                    <Ionicons name="mail-outline" size={18} color={colors.textMuted} style={styles.inputIcon} />
                    <TextInput
                      style={styles.input}
                      placeholder="you@company.com"
                      placeholderTextColor={colors.textMuted}
                      value={email}
                      onChangeText={(t) => { setEmail(t); setErrors((p: any) => ({ ...p, email: '' })); }}
                      autoCapitalize="none"
                      keyboardType="email-address"
                      autoComplete="email"
                    />
                  </View>
                  {errors.email ? <Text style={styles.errorText}>{errors.email}</Text> : null}
                </View>

                {/* Password */}
                <View style={styles.inputGroup}>
                  <View style={styles.labelRow}>
                    <Text style={styles.label}>PASSWORD</Text>
                    <TouchableOpacity onPress={onNavigateForgot}>
                      <Text style={styles.forgotText}>Forgot Password?</Text>
                    </TouchableOpacity>
                  </View>
                  <View style={[styles.inputWrapper, errors.password && styles.inputError]}>
                    <Ionicons name="lock-closed-outline" size={18} color={colors.textMuted} style={styles.inputIcon} />
                    <TextInput
                      style={styles.input}
                      placeholder="••••••••"
                      placeholderTextColor={colors.textMuted}
                      value={password}
                      onChangeText={(t) => { setPassword(t); setErrors((p: any) => ({ ...p, password: '' })); }}
                      secureTextEntry={!showPassword}
                      autoComplete="password"
                    />
                    <TouchableOpacity onPress={() => setShowPassword(!showPassword)} style={styles.eyeBtn}>
                      <Ionicons name={showPassword ? 'eye-off-outline' : 'eye-outline'} size={20} color={colors.textMuted} />
                    </TouchableOpacity>
                  </View>
                  {errors.password ? <Text style={styles.errorText}>{errors.password}</Text> : null}
                </View>

                {/* Login Button */}
                <TouchableOpacity
                  style={[styles.primaryBtn, loading && styles.btnDisabled]}
                  onPress={handleLogin}
                  disabled={loading}
                  activeOpacity={0.8}
                >
                  {loading ? (
                    <ActivityIndicator size="small" color="#fff" />
                  ) : (
                    <Ionicons name="log-in-outline" size={18} color="#fff" />
                  )}
                  <Text style={styles.primaryBtnText}>
                    {loading ? 'Signing In...' : 'Sign In'}
                  </Text>
                </TouchableOpacity>

                {/* Divider */}
                <View style={styles.divider}>
                  <View style={styles.dividerLine} />
                  <Text style={styles.dividerText}>Security features</Text>
                  <View style={styles.dividerLine} />
                </View>

                {/* Security badges */}
                <View style={styles.badgeRow}>
                  <View style={styles.secBadge}>
                    <Ionicons name="hardware-chip-outline" size={14} color={colors.pass} />
                    <Text style={styles.secBadgeText}>Post-Quantum</Text>
                  </View>
                  <View style={styles.secBadge}>
                    <Ionicons name="lock-closed" size={14} color={colors.safe} />
                    <Text style={styles.secBadgeText}>AES-256</Text>
                  </View>
                  <View style={styles.secBadge}>
                    <Ionicons name="shield" size={14} color={colors.scan} />
                    <Text style={styles.secBadgeText}>4-Layer Pipeline</Text>
                  </View>
                </View>
              </>
            )}
          </View>

          {/* Footer */}
          <View style={styles.footer}>
            <Text style={styles.footerText}>Don't have an account? </Text>
            <TouchableOpacity onPress={onNavigateSignup}>
              <Text style={styles.footerLink}>Create Account</Text>
            </TouchableOpacity>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>

    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.bgDeep,
  },
  topAccent: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    height: 200,
    overflow: 'hidden',
  },
  gradientOverlay: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: colors.bgDeep,
    opacity: 0.9,
  },
  keyboardView: {
    flex: 1,
  },
  scrollContent: {
    flexGrow: 1,
    paddingHorizontal: spacing.xl,
    paddingTop: Platform.OS === 'ios' ? 80 : 60,
    paddingBottom: spacing['3xl'],
  },
  logoSection: {
    alignItems: 'center',
    marginBottom: spacing['3xl'],
  },
  logoIcon: {
    width: 64,
    height: 64,
    borderRadius: borderRadius.lg,
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(59, 130, 246, 0.2)',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: spacing.md,
  },
  logoText: {
    fontFamily: 'monospace',
    fontSize: fontSizes['2xl'],
    fontWeight: '700',
    color: colors.textPrimary,
  },
  logoSubtext: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textMuted,
    marginTop: spacing.xs,
  },
  card: {
    backgroundColor: colors.bgSurface,
    borderRadius: borderRadius.xl,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    padding: spacing['2xl'],
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.3,
    shadowRadius: 24,
    elevation: 12,
  },
  cardTitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xl,
    fontWeight: '600',
    color: colors.textPrimary,
    textAlign: 'center',
    marginBottom: spacing.sm,
  },
  cardSubtitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.textMuted,
    textAlign: 'center',
    marginBottom: spacing['2xl'],
  },
  inputGroup: {
    marginBottom: spacing.xl,
  },
  label: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    fontWeight: '600',
    color: colors.textSecondary,
    letterSpacing: 0.5,
    marginBottom: spacing.sm,
  },
  labelRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: spacing.sm,
  },
  forgotText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.accent,
  },
  inputWrapper: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: colors.bgElevated,
    borderRadius: borderRadius.md,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    paddingHorizontal: spacing.md,
  },
  inputError: {
    borderColor: colors.threat,
  },
  inputIcon: {
    marginRight: spacing.sm,
  },
  input: {
    flex: 1,
    paddingVertical: Platform.OS === 'ios' ? spacing.md : spacing.sm,
    color: colors.textPrimary,
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
  },
  eyeBtn: {
    padding: spacing.xs,
  },
  errorText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.threat,
    marginTop: spacing.xs,
  },
  primaryBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.sm,
    backgroundColor: colors.accent,
    borderRadius: borderRadius.md,
    paddingVertical: spacing.lg,
    marginTop: spacing.sm,
  },
  btnDisabled: {
    opacity: 0.6,
  },
  primaryBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    fontWeight: '600',
    color: '#fff',
    letterSpacing: 0.5,
    textTransform: 'uppercase',
  },
  divider: {
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: spacing.xl,
  },
  dividerLine: {
    flex: 1,
    height: 1,
    backgroundColor: colors.bgBorder,
  },
  dividerText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textMuted,
    marginHorizontal: spacing.md,
  },
  badgeRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
    justifyContent: 'center',
  },
  secBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.xs,
    backgroundColor: colors.bgElevated,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: borderRadius.full,
    borderWidth: 1,
    borderColor: colors.bgBorder,
  },
  secBadgeText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textSecondary,
  },
  unlockingWrap: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: spacing.xl,
  },
  lastLoginText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textMuted,
    textAlign: 'center',
    lineHeight: 18,
    marginTop: spacing.md,
  },
  footer: {
    flexDirection: 'row',
    justifyContent: 'center',
    marginTop: spacing['2xl'],
  },
  footerText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.textMuted,
  },
  footerLink: {
    fontFamily: 'monospace',
    fontSize: fontSizes.sm,
    color: colors.accent,
    fontWeight: '600',
  },
});
