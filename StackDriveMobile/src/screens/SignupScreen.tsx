import React, { useState, useEffect } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView,
  KeyboardAvoidingView, Platform, ActivityIndicator, Modal,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import api from '../services/api';
import EncryptionScene from '../components/EncryptionScene';

interface SignupScreenProps {
  onLogin: (user: any) => void;
  onNavigateLogin: () => void;
}

export default function SignupScreen({ onLogin, onNavigateLogin }: SignupScreenProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<any>({});
  const [step, setStep] = useState<'form' | 'otp' | 'success'>('form');
  const [otp, setOtp] = useState('');
  const [otpLoading, setOtpLoading] = useState(false);
  const [resendTimer, setResendTimer] = useState(0);
  const [createdUser, setCreatedUser] = useState<any>(null);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const { addToast } = useToast();

  const [showServerModal, setShowServerModal] = useState(false);
  const [serverUrl, setServerUrl] = useState('');
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'success' | 'failed'>('idle');
  const [connectionError, setConnectionError] = useState('');

  useEffect(() => {
    const loadUrl = async () => {
      try {
        const currentUrl = await api.getApiBase();
        setServerUrl(currentUrl);
      } catch { /* ignore */ }
    };
    loadUrl();
  }, []);

  const handleTestConnection = async () => {
    if (!serverUrl.trim()) {
      addToast('Please enter a valid URL', 'error');
      return;
    }
    setTestingConnection(true);
    setConnectionStatus('idle');
    setConnectionError('');
    try {
      const res = await api.testConnection(serverUrl);
      if (res.success) {
        setConnectionStatus('success');
      } else {
        setConnectionStatus('failed');
        setConnectionError(res.error);
      }
    } catch (err: any) {
      setConnectionStatus('failed');
      setConnectionError(err.message || 'Unknown network error');
    } finally {
      setTestingConnection(false);
    }
  };

  const handleSaveServerUrl = async () => {
    if (!serverUrl.trim()) {
      addToast('URL cannot be empty', 'error');
      return;
    }
    try {
      await api.setCustomApiBase(serverUrl.trim());
      addToast('Server URL saved successfully!', 'success');
      setShowServerModal(false);
    } catch (err: any) {
      addToast(err.message || 'Failed to save server URL', 'error');
    }
  };

  const handleResetServerUrl = async () => {
    try {
      await api.setCustomApiBase(null);
      const defaultUrl = await api.getApiBase();
      setServerUrl(defaultUrl);
      setConnectionStatus('idle');
      setConnectionError('');
      addToast('Reset to default URL', 'success');
    } catch (err: any) {
      addToast(err.message || 'Failed to reset server URL', 'error');
    }
  };

  useEffect(() => {
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendTimer]);

  const validateForm = () => {
    const errs: any = {};
    if (!email) errs.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(email)) errs.email = 'Enter a valid email';
    if (!password) errs.password = 'Password is required';
    else if (password.length < 6) errs.password = 'Minimum 6 characters';
    if (password !== confirmPassword) errs.confirmPassword = 'Passwords do not match';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSendOtp = async () => {
    if (!validateForm()) return;
    setLoading(true);
    try {
      await api.sendOtp(email, 'signup');
      setStep('otp');
      setResendTimer(30);
      addToast('Verification code sent to your email', 'success');
    } catch (err: any) {
      if (err.status === 409) {
        setErrors({ email: 'An account with this email already exists' });
      } else {
        addToast(err.message || 'Failed to send verification code', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAndSignup = async () => {
    if (!otp || otp.length !== 6) {
      setErrors({ otp: 'Please enter 6-digit code' });
      return;
    }
    setOtpLoading(true);
    try {
      await api.verifyOtp(email, otp, 'signup');
      const data = await api.signup(email, password, true);
      setCreatedUser(data.user);

      // Play cinematic unlock before showing success
      setIsUnlocking(true);
      setTimeout(() => {
        setStep('success');
      }, 2500);
    } catch (err: any) {
      if (err.status === 400) {
        setErrors({ otp: 'Invalid or expired OTP' });
      } else {
        addToast(err.message || 'Signup failed', 'error');
      }
    } finally {
      setOtpLoading(false);
    }
  };

  const handleResendOtp = async () => {
    try {
      setResendTimer(30);
      await api.sendOtp(email, 'signup');
      addToast('Verification code resent!', 'success');
    } catch (err: any) {
      addToast(err.message || 'Failed to resend code', 'error');
    }
  };

  const handleContinue = () => {
    onLogin(createdUser);
    addToast('Account created! Connect your AWS account to start.', 'success');
  };

  if (step === 'success') {
    return (
      <View style={styles.container}>
        <View style={styles.successContent}>
          <View style={styles.successIconBg}>
            <Ionicons name="checkmark-circle" size={64} color={colors.safe} />
          </View>
          <Text style={styles.successTitle}>Email Verified!</Text>
          <Text style={styles.successSub}>
            Your account has been created and verified. Tap below to continue to your dashboard.
          </Text>
          <TouchableOpacity style={styles.primaryBtn} onPress={handleContinue} activeOpacity={0.8}>
            <Text style={styles.primaryBtnText}>Continue to Dashboard</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={{ flex: 1 }}>
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
          keyboardShouldPersistTaps="handled"
        >
          {/* Padlock Scene */}
          <EncryptionScene isUnlocking={isUnlocking} />

          {/* Logo */}
          <View style={styles.logoSection}>
            <Text style={styles.logoText}>StackDrive</Text>
          </View>

          <View style={styles.card}>
            {isUnlocking ? (
              <View style={{ alignItems: 'center', paddingVertical: spacing.xl }}>
                <Text style={styles.cardTitle}>Verifying Identity...</Text>
                <ActivityIndicator size="large" color={colors.accent} style={{ marginTop: spacing.xl }} />
              </View>
            ) : step === 'form' ? (
              <>
                <Text style={styles.cardTitle}>Create Account</Text>
                <Text style={styles.cardSubtitle}>Start securing your file uploads today</Text>

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
                    />
                  </View>
                  {errors.email ? <Text style={styles.errorText}>{errors.email}</Text> : null}
                </View>

                <View style={styles.inputGroup}>
                  <Text style={styles.label}>PASSWORD</Text>
                  <View style={[styles.inputWrapper, errors.password && styles.inputError]}>
                    <Ionicons name="lock-closed-outline" size={18} color={colors.textMuted} style={styles.inputIcon} />
                    <TextInput
                      style={styles.input}
                      placeholder="Min 6 characters"
                      placeholderTextColor={colors.textMuted}
                      value={password}
                      onChangeText={(t) => { setPassword(t); setErrors((p: any) => ({ ...p, password: '' })); }}
                      secureTextEntry={!showPassword}
                    />
                    <TouchableOpacity onPress={() => setShowPassword(!showPassword)} style={styles.eyeBtn}>
                      <Ionicons name={showPassword ? 'eye-off-outline' : 'eye-outline'} size={20} color={colors.textMuted} />
                    </TouchableOpacity>
                  </View>
                  {errors.password ? <Text style={styles.errorText}>{errors.password}</Text> : null}
                </View>

                <View style={styles.inputGroup}>
                  <Text style={styles.label}>CONFIRM PASSWORD</Text>
                  <View style={[styles.inputWrapper, errors.confirmPassword && styles.inputError]}>
                    <Ionicons name="lock-closed-outline" size={18} color={colors.textMuted} style={styles.inputIcon} />
                    <TextInput
                      style={styles.input}
                      placeholder="••••••••"
                      placeholderTextColor={colors.textMuted}
                      value={confirmPassword}
                      onChangeText={(t) => { setConfirmPassword(t); setErrors((p: any) => ({ ...p, confirmPassword: '' })); }}
                      secureTextEntry
                    />
                  </View>
                  {errors.confirmPassword ? <Text style={styles.errorText}>{errors.confirmPassword}</Text> : null}
                </View>

                <TouchableOpacity
                  style={[styles.primaryBtn, loading && styles.btnDisabled]}
                  onPress={handleSendOtp}
                  disabled={loading}
                  activeOpacity={0.8}
                >
                  {loading ? <ActivityIndicator size="small" color="#fff" /> : <Ionicons name="person-add-outline" size={18} color="#fff" />}
                  <Text style={styles.primaryBtnText}>{loading ? 'Sending Code...' : 'Create Account'}</Text>
                </TouchableOpacity>
              </>
            ) : (
              <>
                <TouchableOpacity onPress={() => { setStep('form'); setErrors({}); }} style={styles.backBtn}>
                  <Ionicons name="arrow-back" size={18} color={colors.accent} />
                  <Text style={styles.backText}>Back</Text>
                </TouchableOpacity>
                <Text style={styles.cardTitle}>Verify Your Email</Text>
                <Text style={styles.cardSubtitle}>Enter the 6-digit code sent to {email}</Text>

                <View style={styles.inputGroup}>
                  <View style={[styles.inputWrapper, errors.otp && styles.inputError]}>
                    <TextInput
                      style={[styles.input, { textAlign: 'center', fontSize: fontSizes.xl, letterSpacing: 8 }]}
                      placeholder="000000"
                      placeholderTextColor={colors.textMuted}
                      value={otp}
                      onChangeText={(t) => { setOtp(t.replace(/\D/g, '')); setErrors((p: any) => ({ ...p, otp: '' })); }}
                      maxLength={6}
                      keyboardType="number-pad"
                      autoFocus
                    />
                  </View>
                  {errors.otp ? <Text style={[styles.errorText, { textAlign: 'center' }]}>{errors.otp}</Text> : null}
                </View>

                <TouchableOpacity
                  style={[styles.primaryBtn, otpLoading && styles.btnDisabled]}
                  onPress={handleVerifyAndSignup}
                  disabled={otpLoading}
                  activeOpacity={0.8}
                >
                  {otpLoading ? <ActivityIndicator size="small" color="#fff" /> : <Ionicons name="shield-checkmark" size={18} color="#fff" />}
                  <Text style={styles.primaryBtnText}>{otpLoading ? 'Creating Account...' : 'Verify & Create Account'}</Text>
                </TouchableOpacity>

                <View style={styles.resendRow}>
                  {resendTimer > 0 ? (
                    <Text style={styles.resendTimer}>Resend code in {resendTimer}s</Text>
                  ) : (
                    <TouchableOpacity onPress={handleResendOtp}>
                      <Text style={styles.resendLink}>Resend Code</Text>
                    </TouchableOpacity>
                  )}
                </View>
              </>
            )}
          </View>

          <View style={styles.footer}>
            <Text style={styles.footerText}>Already have an account? </Text>
            <TouchableOpacity onPress={onNavigateLogin}>
              <Text style={styles.footerLink}>Sign In</Text>
            </TouchableOpacity>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>

      {/* Floating Settings Gear */}
      <TouchableOpacity
        style={styles.settingsGear}
        onPress={() => setShowServerModal(true)}
        activeOpacity={0.7}
      >
        <Ionicons name="server-outline" size={22} color={colors.textSecondary} />
      </TouchableOpacity>

      {/* Connection Settings Modal */}
      <Modal
        visible={showServerModal}
        animationType="slide"
        transparent={true}
        onRequestClose={() => setShowServerModal(false)}
      >
        <View style={styles.modalOverlay}>
          <KeyboardAvoidingView
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
            style={styles.modalKeyboardView}
          >
            <View style={styles.modalContent}>
              <View style={styles.modalHeader}>
                <Ionicons name="server" size={22} color={colors.accent} />
                <Text style={styles.modalTitle}>Gateway Settings</Text>
                <TouchableOpacity onPress={() => setShowServerModal(false)} style={styles.modalCloseBtn}>
                  <Ionicons name="close" size={24} color={colors.textSecondary} />
                </TouchableOpacity>
              </View>

              <ScrollView style={styles.modalScroll} keyboardShouldPersistTaps="handled">
                <Text style={styles.modalSubtitle}>
                  Configure the backend connection for StackDrive. If you are hosting on an Ubuntu server, enter its address below.
                </Text>

                <View style={styles.inputGroup}>
                  <Text style={styles.label}>SERVER API GATEWAY URL</Text>
                  <View style={styles.inputWrapper}>
                    <Ionicons name="globe-outline" size={18} color={colors.textMuted} style={styles.inputIcon} />
                    <TextInput
                      style={styles.input}
                      placeholder="http://192.168.1.100:5000/api"
                      placeholderTextColor={colors.textMuted}
                      value={serverUrl}
                      onChangeText={(t) => { setServerUrl(t); setConnectionStatus('idle'); }}
                      autoCapitalize="none"
                      autoCorrect={false}
                    />
                  </View>
                </View>

                {connectionStatus === 'success' && (
                  <View style={[styles.statusBadge, styles.successBadge]}>
                    <Ionicons name="checkmark-circle" size={16} color={colors.safe} />
                    <Text style={styles.successBadgeText}>Connection successful!</Text>
                  </View>
                )}

                {connectionStatus === 'failed' && (
                  <View style={[styles.statusBadge, styles.failedBadge]}>
                    <Ionicons name="alert-circle" size={16} color={colors.threat} />
                    <Text style={styles.failedBadgeText}>
                      Connection failed: {connectionError}
                    </Text>
                  </View>
                )}

                <View style={styles.modalActionsRow}>
                  <TouchableOpacity
                    style={[styles.modalBtn, styles.testBtn]}
                    onPress={handleTestConnection}
                    disabled={testingConnection}
                  >
                    {testingConnection ? (
                      <ActivityIndicator size="small" color={colors.accent} />
                    ) : (
                      <>
                        <Ionicons name="wifi-outline" size={16} color={colors.accent} />
                        <Text style={styles.testBtnText}>Test Connection</Text>
                      </>
                    )}
                  </TouchableOpacity>

                  <TouchableOpacity
                    style={[styles.modalBtn, styles.resetBtn]}
                    onPress={handleResetServerUrl}
                  >
                    <Ionicons name="refresh-outline" size={16} color={colors.textSecondary} />
                    <Text style={styles.resetBtnText}>Reset Default</Text>
                  </TouchableOpacity>
                </View>

                <TouchableOpacity
                  style={[styles.primaryBtn, { marginTop: spacing.xl }]}
                  onPress={handleSaveServerUrl}
                >
                  <Ionicons name="save-outline" size={18} color="#fff" />
                  <Text style={styles.primaryBtnText}>Save Configuration</Text>
                </TouchableOpacity>
              </ScrollView>
            </View>
          </KeyboardAvoidingView>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgDeep },
  scrollContent: {
    flexGrow: 1,
    paddingHorizontal: spacing.xl,
    paddingTop: Platform.OS === 'ios' ? 70 : 50,
    paddingBottom: spacing['3xl'],
  },
  logoSection: { alignItems: 'center', marginBottom: spacing['3xl'] },
  logoText: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '700', color: colors.textPrimary },
  card: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.xl,
    borderWidth: 1, borderColor: colors.bgBorder, padding: spacing['2xl'],
    shadowColor: '#000', shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.3, shadowRadius: 24, elevation: 12,
  },
  cardTitle: { fontFamily: 'monospace', fontSize: fontSizes.xl, fontWeight: '600', color: colors.textPrimary, textAlign: 'center', marginBottom: spacing.sm },
  cardSubtitle: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, textAlign: 'center', marginBottom: spacing['2xl'] },
  inputGroup: { marginBottom: spacing.xl },
  label: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600', color: colors.textSecondary, letterSpacing: 0.5, marginBottom: spacing.sm },
  inputWrapper: {
    flexDirection: 'row', alignItems: 'center', backgroundColor: colors.bgElevated,
    borderRadius: borderRadius.md, borderWidth: 1, borderColor: colors.bgBorder, paddingHorizontal: spacing.md,
  },
  inputError: { borderColor: colors.threat },
  inputIcon: { marginRight: spacing.sm },
  input: { flex: 1, paddingVertical: Platform.OS === 'ios' ? spacing.md : spacing.sm, color: colors.textPrimary, fontFamily: 'monospace', fontSize: fontSizes.sm },
  eyeBtn: { padding: spacing.xs },
  errorText: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.threat, marginTop: spacing.xs },
  primaryBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm,
    backgroundColor: colors.accent, borderRadius: borderRadius.md, paddingVertical: spacing.lg, marginTop: spacing.sm,
  },
  btnDisabled: { opacity: 0.6 },
  primaryBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600', color: '#fff', letterSpacing: 0.5, textTransform: 'uppercase' },
  footer: { flexDirection: 'row', justifyContent: 'center', marginTop: spacing['2xl'] },
  footerText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted },
  footerLink: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.accent, fontWeight: '600' },
  backBtn: { flexDirection: 'row', alignItems: 'center', gap: spacing.xs, marginBottom: spacing.lg },
  backText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.accent },
  resendRow: { alignItems: 'center', marginTop: spacing.xl },
  resendTimer: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted },
  resendLink: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.accent, fontWeight: '600' },
  successContent: { flex: 1, justifyContent: 'center', alignItems: 'center', paddingHorizontal: spacing['3xl'] },
  successIconBg: {
    width: 100, height: 100, borderRadius: 50, backgroundColor: 'rgba(34, 197, 94, 0.1)',
    alignItems: 'center', justifyContent: 'center', marginBottom: spacing['2xl'],
  },
  successTitle: { fontFamily: 'monospace', fontSize: fontSizes['2xl'], fontWeight: '600', color: colors.textPrimary, marginBottom: spacing.md },
  successSub: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, textAlign: 'center', marginBottom: spacing['3xl'], lineHeight: 22 },
  settingsGear: {
    position: 'absolute',
    top: Platform.OS === 'ios' ? 50 : 30,
    right: 20,
    zIndex: 10,
    padding: 10,
    backgroundColor: colors.bgSurface,
    borderRadius: borderRadius.full,
    borderWidth: 1,
    borderColor: colors.bgBorder,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(15, 23, 42, 0.75)',
    justifyContent: 'center',
    padding: spacing.xl,
  },
  modalKeyboardView: {
    justifyContent: 'center',
  },
  modalContent: {
    backgroundColor: colors.bgSurface,
    borderRadius: borderRadius.xl,
    borderWidth: 1,
    borderColor: colors.bgBorder,
    padding: spacing.xl,
    maxHeight: '90%',
  },
  modalHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  modalTitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.lg,
    fontWeight: '600',
    color: colors.textPrimary,
    marginLeft: spacing.sm,
    flex: 1,
  },
  modalCloseBtn: {
    padding: spacing.xs,
  },
  modalScroll: {
    marginTop: spacing.sm,
  },
  modalSubtitle: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textMuted,
    lineHeight: 18,
    marginBottom: spacing.xl,
  },
  modalActionsRow: {
    flexDirection: 'row',
    gap: spacing.md,
    marginTop: spacing.md,
  },
  modalBtn: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: spacing.xs,
    paddingVertical: spacing.md,
    borderRadius: borderRadius.md,
    borderWidth: 1,
  },
  testBtn: {
    borderColor: colors.accent,
    backgroundColor: 'rgba(59, 130, 246, 0.05)',
  },
  testBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.accent,
    fontWeight: '600',
  },
  resetBtn: {
    borderColor: colors.bgBorder,
    backgroundColor: colors.bgElevated,
  },
  resetBtnText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.textSecondary,
    fontWeight: '600',
  },
  statusBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    padding: spacing.md,
    borderRadius: borderRadius.md,
    marginTop: spacing.md,
    borderWidth: 1,
  },
  successBadge: {
    backgroundColor: 'rgba(34, 197, 94, 0.05)',
    borderColor: 'rgba(34, 197, 94, 0.2)',
  },
  successBadgeText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.safe,
  },
  failedBadge: {
    backgroundColor: 'rgba(239, 68, 68, 0.05)',
    borderColor: 'rgba(239, 68, 68, 0.2)',
  },
  failedBadgeText: {
    fontFamily: 'monospace',
    fontSize: fontSizes.xs,
    color: colors.threat,
    flex: 1,
  },
});
