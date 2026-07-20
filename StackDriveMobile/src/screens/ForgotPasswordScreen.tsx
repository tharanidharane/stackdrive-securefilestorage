import React, { useState, useEffect } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView,
  KeyboardAvoidingView, Platform, ActivityIndicator,
} from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { colors, spacing, borderRadius, fontSizes } from '../theme/colors';
import { useToast } from '../context/ToastContext';
import api from '../services/api';

interface ForgotPasswordProps {
  onNavigateLogin: () => void;
}

export default function ForgotPasswordScreen({ onNavigateLogin }: ForgotPasswordProps) {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<any>({});
  const [step, setStep] = useState<'email' | 'otp' | 'password'>('email');
  const [resendTimer, setResendTimer] = useState(0);
  const { addToast } = useToast();

  useEffect(() => {
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendTimer]);

  const handleSendOtp = async () => {
    if (!email) { setErrors({ email: 'Email is required' }); return; }
    if (!/\S+@\S+\.\S+/.test(email)) { setErrors({ email: 'Enter a valid email' }); return; }
    setErrors({});
    setLoading(true);
    try {
      await api.sendOtp(email, 'reset');
      setStep('otp');
      setResendTimer(30);
      addToast('Recovery code sent', 'success');
    } catch (err: any) {
      if (err.status === 404) setErrors({ email: 'No account found' });
      else addToast(err.message || 'Failed to send code', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (!otp || otp.length !== 6) { setErrors({ otp: 'Enter the 6-digit code' }); return; }
    setErrors({});
    setLoading(true);
    try {
      await api.verifyOtp(email, otp, 'reset');
      setStep('password');
      addToast('Verified! Choose a new password.', 'success');
    } catch (err: any) {
      if (err.status === 400) setErrors({ otp: 'Invalid or expired OTP' });
      else addToast(err.message || 'Verification failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async () => {
    const errs: any = {};
    if (!password) errs.password = 'Password is required';
    else if (password.length < 6) errs.password = 'Minimum 6 characters';
    if (password !== confirmPassword) errs.confirmPassword = 'Passwords do not match';
    if (Object.keys(errs).length > 0) { setErrors(errs); return; }

    setErrors({});
    setLoading(true);
    try {
      await api.resetPassword(email, password);
      addToast('Password updated successfully!', 'success');
      setTimeout(() => onNavigateLogin(), 1000);
    } catch (err: any) {
      addToast(err.message || 'Failed to reset password', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={styles.container}>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={{ flex: 1 }}>
        <ScrollView contentContainerStyle={styles.scrollContent} showsVerticalScrollIndicator={false} keyboardShouldPersistTaps="handled">
          <View style={styles.logoSection}>
            <View style={styles.logoIcon}>
              <Ionicons name="key" size={32} color={colors.accent} />
            </View>
            <Text style={styles.logoText}>Secure Your Account</Text>
          </View>

          <View style={styles.card}>
            <Text style={styles.subtitle}>
              {step === 'email' && 'Enter your email to receive a recovery code'}
              {step === 'otp' && `Enter the 6-digit code sent to ${email}`}
              {step === 'password' && 'Create a secure new password'}
            </Text>

            {step === 'email' && (
              <>
                <View style={styles.inputGroup}>
                  <Text style={styles.label}>EMAIL ADDRESS</Text>
                  <View style={[styles.inputWrapper, errors.email && styles.inputError]}>
                    <Ionicons name="mail-outline" size={18} color={colors.textMuted} style={styles.inputIcon} />
                    <TextInput
                      style={styles.input}
                      placeholder="you@company.com"
                      placeholderTextColor={colors.textMuted}
                      value={email}
                      onChangeText={(t) => { setEmail(t); setErrors({}); }}
                      autoCapitalize="none"
                      keyboardType="email-address"
                    />
                  </View>
                  {errors.email ? <Text style={styles.errorText}>{errors.email}</Text> : null}
                </View>
                <TouchableOpacity style={[styles.primaryBtn, loading && styles.btnDisabled]} onPress={handleSendOtp} disabled={loading}>
                  {loading ? <ActivityIndicator size="small" color="#fff" /> : null}
                  <Text style={styles.primaryBtnText}>{loading ? 'Sending...' : 'Send Recovery Code'}</Text>
                </TouchableOpacity>
              </>
            )}

            {step === 'otp' && (
              <>
                <View style={styles.inputGroup}>
                  <View style={[styles.inputWrapper, errors.otp && styles.inputError]}>
                    <TextInput
                      style={[styles.input, { textAlign: 'center', fontSize: fontSizes.xl, letterSpacing: 8 }]}
                      placeholder="000000"
                      placeholderTextColor={colors.textMuted}
                      value={otp}
                      onChangeText={(t) => { setOtp(t.replace(/\D/g, '')); setErrors({}); }}
                      maxLength={6}
                      keyboardType="number-pad"
                      autoFocus
                    />
                  </View>
                  {errors.otp ? <Text style={[styles.errorText, { textAlign: 'center' }]}>{errors.otp}</Text> : null}
                </View>
                <TouchableOpacity style={[styles.primaryBtn, loading && styles.btnDisabled]} onPress={handleVerifyOtp} disabled={loading}>
                  {loading ? <ActivityIndicator size="small" color="#fff" /> : null}
                  <Text style={styles.primaryBtnText}>{loading ? 'Verifying...' : 'Verify Code'}</Text>
                </TouchableOpacity>
                <View style={styles.resendRow}>
                  {resendTimer > 0 ? (
                    <Text style={styles.resendTimer}>Resend in {resendTimer}s</Text>
                  ) : (
                    <TouchableOpacity onPress={async () => { setResendTimer(30); await api.sendOtp(email, 'reset'); addToast('Code resent', 'success'); }}>
                      <Text style={styles.resendLink}>Resend Code</Text>
                    </TouchableOpacity>
                  )}
                </View>
              </>
            )}

            {step === 'password' && (
              <>
                <View style={styles.inputGroup}>
                  <Text style={styles.label}>NEW PASSWORD</Text>
                  <View style={[styles.inputWrapper, errors.password && styles.inputError]}>
                    <Ionicons name="lock-closed-outline" size={18} color={colors.textMuted} style={styles.inputIcon} />
                    <TextInput
                      style={styles.input}
                      placeholder="••••••••"
                      placeholderTextColor={colors.textMuted}
                      value={password}
                      onChangeText={(t) => { setPassword(t); setErrors({}); }}
                      secureTextEntry={!showPassword}
                    />
                    <TouchableOpacity onPress={() => setShowPassword(!showPassword)}>
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
                      onChangeText={(t) => { setConfirmPassword(t); setErrors({}); }}
                      secureTextEntry
                    />
                  </View>
                  {errors.confirmPassword ? <Text style={styles.errorText}>{errors.confirmPassword}</Text> : null}
                </View>
                <TouchableOpacity style={[styles.primaryBtn, loading && styles.btnDisabled]} onPress={handleResetPassword} disabled={loading}>
                  {loading ? <ActivityIndicator size="small" color="#fff" /> : null}
                  <Text style={styles.primaryBtnText}>{loading ? 'Updating...' : 'Reset Password'}</Text>
                </TouchableOpacity>
              </>
            )}
          </View>

          <TouchableOpacity onPress={step === 'email' ? onNavigateLogin : () => setStep('email')} style={styles.backRow}>
            <Ionicons name="arrow-back" size={16} color={colors.accent} />
            <Text style={styles.backText}>{step === 'email' ? 'Back to Log In' : 'Change Email'}</Text>
          </TouchableOpacity>
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bgDeep },
  scrollContent: { flexGrow: 1, paddingHorizontal: spacing.xl, paddingTop: Platform.OS === 'ios' ? 80 : 60, paddingBottom: spacing['3xl'] },
  logoSection: { alignItems: 'center', marginBottom: spacing['3xl'] },
  logoIcon: {
    width: 64, height: 64, borderRadius: borderRadius.lg,
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    borderWidth: 1, borderColor: 'rgba(59, 130, 246, 0.2)',
    alignItems: 'center', justifyContent: 'center', marginBottom: spacing.lg,
  },
  logoText: { fontFamily: 'monospace', fontSize: fontSizes.xl, fontWeight: '600', color: colors.textPrimary },
  card: {
    backgroundColor: colors.bgSurface, borderRadius: borderRadius.xl,
    borderWidth: 1, borderColor: colors.bgBorder, padding: spacing['2xl'],
  },
  subtitle: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted, textAlign: 'center', marginBottom: spacing['2xl'] },
  inputGroup: { marginBottom: spacing.xl },
  label: { fontFamily: 'monospace', fontSize: fontSizes.xs, fontWeight: '600', color: colors.textSecondary, letterSpacing: 0.5, marginBottom: spacing.sm },
  inputWrapper: {
    flexDirection: 'row', alignItems: 'center', backgroundColor: colors.bgElevated,
    borderRadius: borderRadius.md, borderWidth: 1, borderColor: colors.bgBorder, paddingHorizontal: spacing.md,
  },
  inputError: { borderColor: colors.threat },
  inputIcon: { marginRight: spacing.sm },
  input: { flex: 1, paddingVertical: Platform.OS === 'ios' ? spacing.md : spacing.sm, color: colors.textPrimary, fontFamily: 'monospace', fontSize: fontSizes.sm },
  errorText: { fontFamily: 'monospace', fontSize: fontSizes.xs, color: colors.threat, marginTop: spacing.xs },
  primaryBtn: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm,
    backgroundColor: colors.accent, borderRadius: borderRadius.md, paddingVertical: spacing.lg,
  },
  btnDisabled: { opacity: 0.6 },
  primaryBtnText: { fontFamily: 'monospace', fontSize: fontSizes.sm, fontWeight: '600', color: '#fff', textTransform: 'uppercase', letterSpacing: 0.5 },
  resendRow: { alignItems: 'center', marginTop: spacing.xl },
  resendTimer: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.textMuted },
  resendLink: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.accent, fontWeight: '600' },
  backRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: spacing.sm, marginTop: spacing['2xl'] },
  backText: { fontFamily: 'monospace', fontSize: fontSizes.sm, color: colors.accent },
});
